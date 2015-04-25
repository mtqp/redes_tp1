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
        header += ",Probability,Event Information\n"
        
        csv = open(statistics_file,"w")
        csv.write(header)
        for message in all_messages:
            message_count = self.messages[message]
            message_probability = float(message_count)/self.count
            
            event_information = (-1) * math.log(message_probability, base_2)
            entropy += message_probability * event_information
            
            csv.write(parse(message) + "," + str(self.messages[message]) + "," + str(message_probability) + "," + str(event_information) + "\n")
            
        csv.write("Source entropy\n")
        csv.write(str(entropy) + "\n")
        
        csv.write("Max entropy\n")
        csv.write(str(math.log(self.count)))
        csv.close()
