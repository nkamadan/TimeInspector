# TimeInspector
Code artifact for the paper "TimeInspector: A Static Analysis Approach for Detecting Timing Attacks" published in the SILM workshop at EuroS&P 2023.

## Abstract
We present a static analysis approach to detect malicious binaries that are capable of carrying out a timing attack. The proposed approach is based on a simple observation that the timing attacks typically operate by measuring the execution times of short sequences of instructions.

## Install & Use

This will install radare2 and r2pipe in a virtual environment.

```sh
git clone https://github.com/nkamadan/TimeInspector.git
./setup.sh
```

```
usage: main.py [-h] [-d] [-f FILE]

options:
  -h, --help            show this help message and exit
  -d, --dependency      open dependency
  -f FILE, --file FILE  file name
```


## Citation

```
@inproceedings{durmaz2023timeinspector,
  title={TimeInspector: A Static Analysis Approach for Detecting Timing Attacks},
  author={Durmaz, Fatih and Kamadan, Nureddin and {\"O}z, Melih Taha and Unal, Musa and Javeed, Arsalan and Yilmaz, Cemal and Savas, Erkay},
  booktitle={2023 IEEE European Symposium on Security and Privacy Workshops (EuroS\&PW)},
  pages={296--303},
  year={2023},
  organization={IEEE Computer Society}
}
```
