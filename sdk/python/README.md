# Oracle Cloud Infrastructure Resource Provider

The Oracle Cloud Infrastructure (OCI) Resource Provider lets you manage [OCI](https://www.oracle.com/cloud/) resources.

## Installing

This package is available for several languages/platforms:

### Node.js (JavaScript/TypeScript)

To use with JavaScript or TypeScript in Node.js, install using either `npm`:

```bash
npm install @pulumi/oci
```

or `yarn`:

```bash
yarn add @pulumi/oci
```

### Python

To use with Python, install using `pip`:

```bash
python3 -m pip install pulumi_oci
```

### Go

To use with Go, use `go get` to grab the latest version of the library:

```bash
go get github.com/pulumi/pulumi-oci/sdk/...
```

### .NET

To use with .NET, install using `dotnet add package`:

```bash
dotnet add package Pulumi.Oci
```

## Configuration

The following configuration options are available for the `oci` provider:

| Option                   | Environment variable          | Description                                                                                                                 |
| ------------------------ | ----------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `oci:tenancyOcid`        | `TF_VAR_tenancy_ocid`         | OCID of your tenancy.                                                                                                       |
| `oci:userOcid`           | `TF_VAR_user_ocid`            | OCID of the user calling the API.                                                                                           |
| `oci:privateKey`         | `TF_VAR_private_key`          | The contents of the private key file. Required if `privateKeyPath` is not defined and takes precedence if both are defined. |
| `oci:privateKeyPath`     | `TF_VAR_private_key_path`     | The path (including filename) of the private key stored on your computer. Required if `privateKey` is not defined.          |
| `oci:privateKeyPassword` | `TF_VAR_private_key_password` | Passphrase used for the key, if it is encrypted.                                                                            |
| `oci:fingerprint`        | `TF_VAR_fingerprint`          | Fingerprint for the key pair being used.                                                                                    |
| `oci:region`             | `TF_VAR_region`               | An OCI region.                                                                                                              |
| `oci:configFileProfile`  | `TF_VAR_config_file_profile`  | The custom profile to use instead of the `DEFAULT` profile in `.oci/config`.             |

Use the [Required Keys and OCIDs](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#Required_Keys_and_OCIDs) chapter of the OCI Developer Guide to learn:

- [How to Generate an API Signing Key](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#two)
- [How to Get the Key's Fingerprint](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#four)
- [Where to Get the Tenancy's OCID and User's OCID](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#five)

## Reference

For detailed reference documentation, please visit [the Pulumi registry](https://www.pulumi.com/registry/packages/oci/api-docs/).
