from setuptools import setup, find_packages

with open("requirements.txt", "r") as f:
    requirements = [line[:-1] for line in f.readlines()]

setup(
    name='fast-boot-security',
    version='0.0.1',
    license='MIT',
    author="TikTzuki",
    author_email='tranphanthanhlong18@gmail.com',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    url='https://github.com/TikTzuki/fast-boot-security',
    keywords='fast boot',
    install_requires=requirements
)
