[![ci](https://github.com/jkittner/sri-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/jkittner/sri-checker/actions/workflows/ci.yml)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/jkittner/sri-checker/main.svg)](https://results.pre-commit.ci/latest/github/jkittner/sri-checker/main)

# sri-checker

A code formatter to add double indentation to function and method definitions.

## Installation

`pip install sri-checker`

## usage

```console
usage: sri-checker [-h] [filenames ...]

positional arguments:
  filenames

options:
  -h, --help  show this help message and exit
```

## pre-commit hook

See [pre-commit](https://pre-commit.com) for instructions

Sample `.pre-commit-config.yaml`:

```yaml
- repo: https://github.com/jkittner/sri-checker
  rev: 0.1.0
  hooks:
    - id: sri-checker
```

**If you are using public CDNs in any of your html-files and [pre-commit.ci](https://pre-commit.ci), you have to add this section to your `.pre-commit-config.yaml` since there is no access to the internet during setup or runtime in pre-commit.ci**

```yaml
ci:
  skip: [sri-checker]
```

## Example

With an html-file `base.html`:

```html
<link
  href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"
  rel="stylesheet"
  integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL"
  crossorigin="anonymous"
/>
```

```bash
sri-checker base.html
```

This will return an error end exit with `1`.

```console
t.html:1 SRI-hash incorrect
expected: sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN
got: sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL

```

Contents can also be passed via stdin:

```bash
cat t.html | sri-checker -
```
