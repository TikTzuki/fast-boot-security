from setuptools import setup, find_packages

setup(
    name='fast-boot-security',
    version='0.0.12',
    license='MIT',
    author="TikTzuki",
    author_email='tranphanthanhlong18@gmail.com',
    packages=find_packages(".", include=["fast_boot*"]),
    package_dir={'': '.'},
    url='https://github.com/TikTzuki/fast-boot-security',
    keywords='fast boot security',
    install_requires=[
        'fastapi>=0.65.2'
        'loguru>=0.5.3'
        'orjson>=3.5.4'
    ]
)
