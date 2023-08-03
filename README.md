# TOSS STIG

Source code repository for the TOSS STIG.

The STIG content files can be downloaded from DISA's website: <https://public.cyber.mil/stigs/downloads/>

For the Ansible playbook that implements this stig, see the [ansible](/ansible) directory.

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
