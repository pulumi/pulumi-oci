# Oracle Cloud (OCI) Resource Provider

The Oracle Cloud (OCI) Resource Provider lets you manage [Oracle Cloud](https://www.oracle.com/index.html) resources.

## Installing

This package is available for several languages/platforms:

### Node.js (JavaScript/TypeScript)

To use from JavaScript or TypeScript in Node.js, install using either `npm`:

```bash
npm install @pulumi/oci
```

or `yarn`:

```bash
yarn add @pulumi/oci
```

### Python

To use from Python, install using `pip`:

```bash
pip install pulumi_oci
```

### Go

To use from Go, use `go get` to grab the latest version of the library:

```bash
go get github.com/pulumi/pulumi-oci/sdk/...
```

### .NET

To use from .NET, install using `dotnet add package`:

```bash
dotnet add package Pulumi.Oci
```

## Configuration

The following configuration points are available for the `oci` provider:

- `oci:tenancyOcid` (environment: `TF_VAR_tenancy_ocid`) - OCID of your tenancy. To get the value, see [Where to Get the Tenancy's OCID and User's OCID](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#five.
- `oci:userOcid` (environment: `TF_VAR_user_ocid`) - OCID of the user calling the API. To get the value, see [Where to Get the Tenancy's OCID and User's OCID](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#five).
- `oci:privateKey` (environment: `TF_VAR_private_key`) - The contents of the private key file. Required if `privateKeyPath` is not defined, and takes precedence over `privateKeyPath` if both are defined. For details on how to create and configure keys see [How to Generate an API Signing Key](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#two)) and [How to Upload the Public Key](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#three).
- `oci:privateKeyPath` (environment: `TF_VAR_private_key_path`) - The path (including filename) of the private key stored on your computer. Required if `privateKey` is not defined. For details on how to create and configure keys see [How to Generate an API Signing Key](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#two)) and [How to Upload the Public Key](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#three).
- `oci:privateKeyPassword` (environment: `TF_VAR_private_key_password`) - Passphrase used for the key, if it is encrypted.
- `oci:fingerprint` (environment: `TF_VAR_fingerprint`) - Fingerprint for the key pair being used. To get the value, see [How to Get the Key's Fingerprint](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#four).
- `oci:region` (environment: `TF_VAR_region`) - An OCI region. See [Regions and Availability Domains](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm#top).
- `oci:configFileProfile` (environment: `TF_VAR_config_file_profile`) - The profile name if you would like to use a custom profile in the OCI config file to provide the authentication credentials. See [Using the SDK and CLI Configuration File](https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/terraformproviderconfiguration.htm#terraformproviderconfiguration_topic-SDK_and_CLI_Config_File) for more information.


## Reference

For detailed reference documentation, please visit [the Pulumi registry](https://www.pulumi.com/registry/packages/oci/api-docs/).
