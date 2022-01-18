
from abc import ABC, abstractmethod

class Transformer(ABC):
    @abstractmethod
    def transform(self,**kwargs):
        pass
    
    @abstractmethod
    def inverse_transform(self,**kwargs):
        pass


# class SymmetricTranformer(Transformer):
#     @abstractmethod
#     def inverse_transform(self,**kwargs):
#         return self.transform(**kwargs)


if __name__ == "__main__":
    pass