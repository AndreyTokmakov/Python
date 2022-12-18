'''
Created on Nov 26, 2020
@author: AndTokm
'''

class Base:
    
    def Public_Function(self):
        print("Public_Function called")
        
    def _Protected_Funcion(self):
        print("_Protected_Funcion called")  
        
    def __Private_Funcion(self):
        print("__Private_Funcion called")
        
        
class Derived(Base):
    
    def CallBaseClass_Public_Method(self):
        # Call using 'Base'
        Base.Public_Function(self);
        
        # Call using 'super()'
        super().Public_Function();
        
        # Call using 'self()'
        self.Public_Function();

    def CallBaseClass_Protected_Method(self):
        # Call using 'Base'
        Base._Protected_Funcion(self);
        
        # Call using 'super()'
        super()._Protected_Funcion();
        
        # Call using 'self()'
        self._Protected_Funcion();
        
    def CallBaseClass_Private_Method(self):

        # Call using 'self()'
        self.__Private_Funcion();

if __name__ == '__main__':
    base = Base();
    
    # base.Public_Function()
    # base.__Private_Funcion()
    
    d = Derived();
    # d.CallBaseClassPublicMethod()
    # d.CallBaseClass_Protected_Method()
    d.CallBaseClass_Private_Method();
    
    
    
    
    
    
    