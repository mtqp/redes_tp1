
class source:
    def __init__(self):
        self.count = 0
        self.packets = dict()
        
    def add_packet(self, key):
        self.count += 1
        if self.packets.has_key(key):
            self.packets[key] += 1
        else:
            self.packets[key] = 1
    
    def save(self, statistics_file, header, key_parser):
        all_keys = self.packets.keys()
        all_keys.sort()

        csv = open(statistics_file,"w")
        csv.write(header + "\n")
        for key in all_keys:
            csv.write(key_parser(key) + "," + str(self.packets[key]) + "\n")
        csv.close()
