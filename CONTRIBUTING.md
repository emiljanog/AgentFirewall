# Contributing

1. Open an issue describing the security problem and realistic threat scenario.
2. Include tests for new policy behavior and false positives.
3. Keep dependencies minimal. Do not upload secrets, private project content or exploit details.
4. Run `python -m unittest discover -s tests -v` before submitting a pull request.
5. Security-sensitive policy changes should describe bypass conditions and compatibility impact.
