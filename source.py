import math

class source:
    def __init__(self):
        self.count = 0
        self.messages = dict()
        
    def add(self, message):
        self.count += 1
        if self.messages.has_key(message):
            self.messages[message] += 1
        else:
            self.messages[message] = 1
    
    def save(self, statistics_file, header, parse):
        all_messages = self.messages.keys()
        all_messages.sort()

        entropy = 0
        base_2 = 2
        header += ",Probability\n"
        
        csv = open(statistics_file,"w")
        csv.write(header)
        for message in all_messages:
            message_count = self.messages[message]
            message_probability = float(message_count)/self.count
            
            message_entropy = message_probability * math.log(message_probability, base_2)
            entropy -= message_entropy
            
            #print "Entropy of: " + parse(message) + " is: " + str(message_entropy)
            #print "Entropy so far is: " + str(entropy)
            
            csv.write(parse(message) + "," + str(self.messages[message]) + "," + str(message_probability) + "\n")
            
        csv.write("Entropy\n")
        csv.write(str(entropy))
        csv.close()
