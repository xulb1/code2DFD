

class CExternalEntity:

    def __init__(self, name):
        self.name = name
        self.stereotypes = []
        self.tagged_values = []

    def add_stereotype(self, stereotype):
        if stereotype not in self.stereotypes:
            self.stereotypes.append(stereotype)
        
    def add_tagged_value(self, tagged_value):
        if tagged_value not in self.tagged_values:
            self.tagged_values.append(tagged_value)
    