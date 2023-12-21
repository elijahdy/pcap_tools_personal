from setuptools import setup, find_packages
import os

# Function to discover all scripts in the 'scripts' directory
def discover_scripts():
    script_files = []
    for folder, _, files in os.walk('scripts'):
        for file in files:
            if file.endswith('.py') and not file.startswith('__'):
                script_files.append(os.path.join(folder, file))
    return script_files

setup(
    name='traffic_generator',
    version='0.1.0',
    packages=find_packages(),
    install_requires=['scapy', 'numpy'],
    scripts=discover_scripts(),
)