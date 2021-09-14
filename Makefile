.DEFAULT_GOAL := build


build: clean
	python setup.py sdist bdist_wheel

publish: build
	twine upload dist/*

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info

