rmdir /s /q venv
python -m virtualenv venv || echo ERRORVENV && exit /b 1
venv\Scripts\pip install --require-hashes -r tools\requirements_dev.txt || echo ERRORPIP && exit /b 1
venv\Scripts\python setup.py pep8 --max-line-length=100  || echo ERRORPEP8 && exit /b 1
venv\Scripts\python setup.py test || echo ERRORTEST && exit /b 1
venv\Scripts\python setup.py sdist || echo ERRORSDIST && exit /b 1

