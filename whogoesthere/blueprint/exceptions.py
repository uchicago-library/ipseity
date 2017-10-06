class Error(Exception):
    err_name = "Error"
    status_code = 500
    message = ""

    def __init__(self, message=None):
        if message is not None:
            self.message = message

    def to_dict(self):
        return {"message": self.message,
                "error_name": self.err_name}


class UserAlreadyExistsError(Error):
    err_name = "UserAlreadyExistsError"
    status_code = 403


class UserDoesNotExistError(Error):
    err_name = "UserDoesNotExistError"
    status_code = 404


class IncorrectPasswordError(Error):
    err_name = "IncorrectPasswordError"
    status_code = 404
