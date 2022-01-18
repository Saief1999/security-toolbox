class Generator:
    def __init__(self) -> None:
        pass
    def generate(self):
        with open("first_names_v3.txt","r") as f1:
            with open("last_names_v3.txt","r") as f2:
                first_name_list=[x.rstrip() for x in f1.readlines()]
                first_name_list = list(filter(self.max_size_firstname ,first_name_list))
                print(first_name_list)
                last_name_list=[x.rstrip() for x in f2.readlines()]
                last_name_list = list(filter(self.max_size_lastname ,last_name_list))
                print(last_name_list)
          
            with open("insat.dic", "w") as f1:
                for firstname in first_name_list:
                    for lastname in last_name_list:
                        f1.write(f"{lastname}.{firstname}@insat.ucar.tn\n")            

    def max_size_firstname(self, s:str):
        return len(s) <= 5
    def max_size_lastname(self, s:str):
        return len(s) <= 6

if __name__=="__main__":
    generator = Generator()
    generator.generate()