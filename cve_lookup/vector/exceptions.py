class InvalidVectorValue(ValueError):
    def __init__(self, vector, vector_list, message=None):
        bad_value = vector_list[vector]
        if message == None:
            if type(bad_value) != str:
                bad_value = type(bad_value).__name__
            self.message = 'The \'{}\' vector cannot be \'{}\''.format(vector, bad_value)
        else:
            self.message = message
        super().__init__(self.message)
