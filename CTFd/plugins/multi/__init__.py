from CTFd.plugins.keys import get_key_class
from CTFd.plugins import challenges
from CTFd.plugins import keys
from CTFd.models import db, Keys, WrongKeys


class MultiChallenge(challenges.BaseChallenge):
    id = 2
    name = "multi-challenge"

    @staticmethod
    def attempt(chal, request):
        provided_key = request.form['key'].strip()
        chal_keys = Keys.query.filter_by(chal=chal.id).all()
        for chal_key in chal_keys:
            if get_key_class(chal_key.key_type).compare(chal_key.flag, provided_key):
                if get_chal_class(chal_key.key_type) == 0:
                    return True, 'Correct'
                if get_chal_class(chal_key.key_type) == 2:
                    return False, 'Incorrect'
        return False, 'Incorrect'

    @staticmethod
    def solve(team, chal, request):
        provided_key = request.form['key'].strip()
        solve = Solves(teamid=team.id, chalid=chal.id, ip=utils.get_ip(req=request), flag=provided_key)
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


class BaseKey(object):
    id = None
    name = None

    @staticmethod
    def compare(self, saved, provided):
        return True


class CTFdWrongKey(BaseKey):
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


def load(app):
    challenges.CHALLENGE_CLASSES[2] = MultiChallenge
    keys.KEY_CLASSES[2] = CTFdWrongKey
