from functools import reduce

print((lambda x,y: lambda z: x+y if z==5 else pow(x,y))(1,2)(5))