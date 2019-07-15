# About:
Simple nginx log parser, implemented as homework task in OTUS python dev course.
Just add your logs to log/ dir and run log_analyzer.py to create report in reports folder.

# How to use:
```python -m log_analyzer.log_analyzer --config ./config/some_config```
`--config` is optional. By default script searches config.json in root dir.

# How to test:
```python -m unittest tests/test_log_analyzer.py```