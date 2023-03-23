# TOSS STIG

Source code repository for TOSS STIG.

Note: As of 2022-12-13, the TOSS STIG is only available on the pki enabled DISA portal: <https://cyber.mil/>

## Log Format

In to Elastic Common Schema (ECS). Something like:

```json
{
    "stig": {
        "name": "toss4",
        "controls": {
            "toss-04-1": {
                "outcome": "success"
            },
            "toss-04-2": {
                "outcome": "success"
            },
            "toss-04-3": {
                "outcome": "failure",
                "reason": "blah"
            },
            "toss-04-4": {
                "outcome": "success"
            },
        }
    }
}
```

## License

Scraper is released under the Apache 2.0 w/ LLVM Exception license. For more details see the [LICENSE](/LICENSE) file.

LLNL-CODE-843196
