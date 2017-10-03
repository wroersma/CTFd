from CTFd.plugins.keys import get_key_class
from CTFd.plugins import challenges
from CTFd.plugins import keys
from CTFd.plugins.keys import BaseKey
from flask import request, redirect, jsonify, url_for, session, abort
from CTFd.models import db, Challenges, Solves, WrongKeys, Keys, Teams, Awards
from CTFd import utils
import logging
import time
from CTFd.plugins.challenges import get_chal_class


class MultiChallenge(challenges.BaseChallenge):
    """Multi-Challenge allows right and wrong answers and leaves the question open"""
    id = 2
    name = "multi-challenge"

    def attempt(chal, request):
        provided_key = request.form['key'].strip()
        chal_keys = Keys.query.filter_by(chal=chal.id).all()
        for chal_key in chal_keys:
            if get_key_class(chal_key.key_type).compare(chal_key.flag, provided_key):
                if chal_key.key_type == 0:
                    return True, 'Correct'
                elif chal_key.key_type == 2:
                    return False, 'Failed Attempt'
        return False, 'Incorrect'

    @staticmethod
    def solve(team, chal, request):
        provided_key = request.form['key'].strip()
        solve = Awards(teamid=team.id, name=chal.id, value=chal.value, description=provided_key)
        db.session.add(solve)
        db.session.commit()
        db.session.close()

    @staticmethod
    def fail(team, chal, request):
        provided_key = request.form['key'].strip()
        wrong = WrongKeys(teamid=team.id, chalid=chal.id, ip=utils.get_ip(request), flag=provided_key)
        db.session.add(wrong)
        db.session.commit()
        db.session.close()

    def wrong(team, chal, request):
        provided_key = request.form['key'].strip()
        wrong_value = 0
        wrong_value -= chal.value
        wrong = WrongKeys(teamid=team.id, chalid=chal.id, ip=utils.get_ip(request), flag=provided_key)
        solve = Awards(teamid=team.id, name=chal.id, value=wrong_value, description=provided_key)
        db.session.add(wrong)
        db.session.add(solve)
        db.session.commit()
        db.session.close()

class CTFdWrongKey(BaseKey):
    """Wrong key to deduct points from the player"""
    id = 2
    name = "Wrong"

    @staticmethod
    def compare(saved, provided):
        if len(saved) != len(provided):
            return False
        result = 0
        for x, y in zip(saved, provided):
            result |= ord(x) ^ ord(y)
        return result == 0


def chal(chalid):
    if utils.ctf_ended() and not utils.view_after_ctf():
        abort(403)
    if not utils.user_can_view_challenges():
        return redirect(url_for('auth.login', next=request.path))
    if (utils.authed() and utils.is_verified() and (utils.ctf_started() or utils.view_after_ctf())) or utils.is_admin():
        team = Teams.query.filter_by(id=session['id']).first()
        fails = WrongKeys.query.filter_by(teamid=session['id'], chalid=chalid).count()
        logger = logging.getLogger('keys')
        data = (time.strftime("%m/%d/%Y %X"), session['username'].encode('utf-8'), request.form['key'].encode('utf-8'), utils.get_kpm(session['id']))
        print("[{0}] {1} submitted {2} with kpm {3}".format(*data))

        # Anti-bruteforce / submitting keys too quickly
        if utils.get_kpm(session['id']) > 10:
            if utils.ctftime():
                wrong = WrongKeys(teamid=session['id'], chalid=chalid, ip=utils.get_ip(), flag=request.form['key'].strip())
                db.session.add(wrong)
                db.session.commit()
                db.session.close()
            logger.warn("[{0}] {1} submitted {2} with kpm {3} [TOO FAST]".format(*data))
            # return '3' # Submitting too fast
            return jsonify({'status': 3, 'message': "You're submitting keys too fast. Slow down."})

        solves = Awards.query.filter_by(teamid=session['id'], name=chalid, description=request.form['key'].strip()).first()

        # Challenge not solved yet
        try:
            flag_value = solves.description
        except AttributeError:
            flag_value = ""
        if request.form['key'].strip() != flag_value or not solves:
            chal = Challenges.query.filter_by(id=chalid).first_or_404()
            provided_key = request.form['key'].strip()
            saved_keys = Keys.query.filter_by(chal=chal.id).all()

            # Hit max attempts
            max_tries = chal.max_attempts
            if max_tries and fails >= max_tries > 0:
                return jsonify({
                    'status': 0,
                    'message': "You have 0 tries remaining"
                })

            chal_class = get_chal_class(chal.type)
            status, message = chal_class.attempt(chal, request)
            if status:  # The challenge plugin says the input is right
                if utils.ctftime() or utils.is_admin():
                    chal_class.solve(team=team, chal=chal, request=request)
                logger.info("[{0}] {1} submitted {2} with kpm {3} [CORRECT]".format(*data))
                return jsonify({'status': 1, 'message': message})
            elif message == "Failed Attempt":
                if utils.ctftime() or utils.is_admin():
                    chal_class.wrong(team=team, chal=chal, request=request)
                logger.info("[{0}] {1} submitted {2} with kpm {3} [Failed Attempt]".format(*data))
                return jsonify({'status': 1, 'message': message})
            else:  # The challenge plugin says the input is wrong
                if utils.ctftime() or utils.is_admin():
                    chal_class.fail(team=team, chal=chal, request=request)
                logger.info("[{0}] {1} submitted {2} with kpm {3} [WRONG]".format(*data))
                # return '0' # key was wrong
                if max_tries:
                    attempts_left = max_tries - fails - 1  # Off by one since fails has changed since it was gotten
                    tries_str = 'tries'
                    if attempts_left == 1:
                        tries_str = 'try'
                    if message[-1] not in '!().;?[]\{\}':  # Add a punctuation mark if there isn't one
                        message = message + '.'
                    return jsonify({'status': 0, 'message': '{} You have {} {} remaining.'.format(message, attempts_left, tries_str)})
                else:
                    return jsonify({'status': 0, 'message': message})

        # Challenge already solved
        else:
            logger.info("{0} submitted {1} with kpm {2} [ALREADY SOLVED]".format(*data))
            # return '2' # challenge was already solved
            return jsonify({'status': 2, 'message': 'You already solved this'})
    else:
        return jsonify({
            'status': -1,
            'message': "You must be logged in to solve a challenge"
        })


def solves(teamid=None):
    solves = None
    awards = None
    if teamid is None:
        if utils.is_admin():
            solves = Solves.query.filter_by(teamid=session['id']).all()
        elif utils.user_can_view_challenges():
            if utils.authed():
                solves = Solves.query.join(Teams, Solves.teamid == Teams.id).filter(Solves.teamid == session['id'], Teams.banned == False).all()
            else:
                return jsonify({'solves': []})
        else:
            return redirect(url_for('auth.login', next='solves'))
    else:
        if utils.hide_scores():
            # Use empty values to hide scores
            solves = []
            awards = []
        else:
            solves = Solves.query.filter_by(teamid=teamid)
            awards = Awards.query.filter_by(teamid=teamid)

            freeze = utils.get_config('freeze')
            if freeze:
                freeze = utils.unix_time_to_utc(freeze)
                if teamid != session.get('id'):
                    solves = solves.filter(Solves.date < freeze)
                    awards = awards.filter(Awards.date < freeze)

            solves = solves.all()
            awards = awards.all()
    db.session.close()
    json = {'solves': []}
    for solve in solves:
        json['solves'].append({
            'chal': solve.chal.name,
            'chalid': solve.chalid,
            'team': solve.teamid,
            'value': solve.chal.value,
            'category': solve.chal.category,
            'time': utils.unix_time(solve.date)
        })
    if awards:
        for award in awards:
            json['solves'].append({
                'chal': award.name,
                'chalid': None,
                'team': award.teamid,
                'value': award.value,
                'category': award.category or "Award",
                'time': utils.unix_time(award.date)
            })
    json['solves'].sort(key=lambda k: k['time'])
    return jsonify(json)


def load(app):
    challenges.CHALLENGE_CLASSES[2] = MultiChallenge
    keys.KEY_CLASSES[2] = CTFdWrongKey
    app.view_functions['challenges.chal'] = chal
    #app.view_functions['models.Multi_Awards'] = Awards
