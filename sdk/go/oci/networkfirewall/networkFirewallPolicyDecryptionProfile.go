// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package networkfirewall

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This resource provides the Network Firewall Policy Decryption Profile resource in Oracle Cloud Infrastructure Network Firewall service.
//
// Creates a new Decryption Profile for the Network Firewall Policy.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/NetworkFirewall"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := NetworkFirewall.NewNetworkFirewallPolicyDecryptionProfile(ctx, "testNetworkFirewallPolicyDecryptionProfile", &NetworkFirewall.NetworkFirewallPolicyDecryptionProfileArgs{
//				NetworkFirewallPolicyId:            pulumi.Any(oci_network_firewall_network_firewall_policy.Test_network_firewall_policy.Id),
//				Type:                               pulumi.Any(_var.Network_firewall_policy_decryption_profile_type),
//				AreCertificateExtensionsRestricted: pulumi.Any(_var.Network_firewall_policy_decryption_profile_are_certificate_extensions_restricted),
//				IsAutoIncludeAltName:               pulumi.Any(_var.Network_firewall_policy_decryption_profile_is_auto_include_alt_name),
//				IsExpiredCertificateBlocked:        pulumi.Any(_var.Network_firewall_policy_decryption_profile_is_expired_certificate_blocked),
//				IsOutOfCapacityBlocked:             pulumi.Any(_var.Network_firewall_policy_decryption_profile_is_out_of_capacity_blocked),
//				IsRevocationStatusTimeoutBlocked:   pulumi.Any(_var.Network_firewall_policy_decryption_profile_is_revocation_status_timeout_blocked),
//				IsUnknownRevocationStatusBlocked:   pulumi.Any(_var.Network_firewall_policy_decryption_profile_is_unknown_revocation_status_blocked),
//				IsUnsupportedCipherBlocked:         pulumi.Any(_var.Network_firewall_policy_decryption_profile_is_unsupported_cipher_blocked),
//				IsUnsupportedVersionBlocked:        pulumi.Any(_var.Network_firewall_policy_decryption_profile_is_unsupported_version_blocked),
//				IsUntrustedIssuerBlocked:           pulumi.Any(_var.Network_firewall_policy_decryption_profile_is_untrusted_issuer_blocked),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// NetworkFirewallPolicyDecryptionProfiles can be imported using the `name`, e.g.
//
// ```sh
//
//	$ pulumi import oci:NetworkFirewall/networkFirewallPolicyDecryptionProfile:NetworkFirewallPolicyDecryptionProfile test_network_firewall_policy_decryption_profile "networkFirewallPolicies/{networkFirewallPolicyId}/decryptionProfiles/{decryptionProfileName}"
//
// ```
type NetworkFirewallPolicyDecryptionProfile struct {
	pulumi.CustomResourceState

	// (Updatable) Whether to block sessions if the server's certificate uses extensions other than key usage and/or extended key usage.
	AreCertificateExtensionsRestricted pulumi.BoolOutput `pulumi:"areCertificateExtensionsRestricted"`
	// (Updatable) Whether to automatically append SAN to impersonating certificate if server certificate is missing SAN.
	IsAutoIncludeAltName pulumi.BoolOutput `pulumi:"isAutoIncludeAltName"`
	// (Updatable) Whether to block sessions if server's certificate is expired.
	IsExpiredCertificateBlocked pulumi.BoolOutput `pulumi:"isExpiredCertificateBlocked"`
	// (Updatable) Whether to block sessions if the firewall is temporarily unable to decrypt their traffic.
	IsOutOfCapacityBlocked pulumi.BoolOutput `pulumi:"isOutOfCapacityBlocked"`
	// (Updatable) Whether to block sessions if the revocation status check for server's certificate does not succeed within the maximum allowed time (defaulting to 5 seconds).
	IsRevocationStatusTimeoutBlocked pulumi.BoolOutput `pulumi:"isRevocationStatusTimeoutBlocked"`
	// (Updatable) Whether to block sessions if the revocation status check for server's certificate results in "unknown".
	IsUnknownRevocationStatusBlocked pulumi.BoolOutput `pulumi:"isUnknownRevocationStatusBlocked"`
	// (Updatable) Whether to block sessions if SSL cipher suite is not supported.
	IsUnsupportedCipherBlocked pulumi.BoolOutput `pulumi:"isUnsupportedCipherBlocked"`
	// (Updatable) Whether to block sessions if SSL version is not supported.
	IsUnsupportedVersionBlocked pulumi.BoolOutput `pulumi:"isUnsupportedVersionBlocked"`
	// (Updatable) Whether to block sessions if server's certificate is issued by an untrusted certificate authority (CA).
	IsUntrustedIssuerBlocked pulumi.BoolOutput `pulumi:"isUntrustedIssuerBlocked"`
	// Name of the decryption profile.
	Name pulumi.StringOutput `pulumi:"name"`
	// Unique Network Firewall Policy identifier
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	NetworkFirewallPolicyId pulumi.StringOutput `pulumi:"networkFirewallPolicyId"`
	// OCID of the Network Firewall Policy this decryption profile belongs to.
	ParentResourceId pulumi.StringOutput `pulumi:"parentResourceId"`
	// Describes the type of decryption profile. The accepted values are - * SSL_FORWARD_PROXY * SSL_INBOUND_INSPECTION
	Type pulumi.StringOutput `pulumi:"type"`
}

// NewNetworkFirewallPolicyDecryptionProfile registers a new resource with the given unique name, arguments, and options.
func NewNetworkFirewallPolicyDecryptionProfile(ctx *pulumi.Context,
	name string, args *NetworkFirewallPolicyDecryptionProfileArgs, opts ...pulumi.ResourceOption) (*NetworkFirewallPolicyDecryptionProfile, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.NetworkFirewallPolicyId == nil {
		return nil, errors.New("invalid value for required argument 'NetworkFirewallPolicyId'")
	}
	if args.Type == nil {
		return nil, errors.New("invalid value for required argument 'Type'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource NetworkFirewallPolicyDecryptionProfile
	err := ctx.RegisterResource("oci:NetworkFirewall/networkFirewallPolicyDecryptionProfile:NetworkFirewallPolicyDecryptionProfile", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetNetworkFirewallPolicyDecryptionProfile gets an existing NetworkFirewallPolicyDecryptionProfile resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetNetworkFirewallPolicyDecryptionProfile(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *NetworkFirewallPolicyDecryptionProfileState, opts ...pulumi.ResourceOption) (*NetworkFirewallPolicyDecryptionProfile, error) {
	var resource NetworkFirewallPolicyDecryptionProfile
	err := ctx.ReadResource("oci:NetworkFirewall/networkFirewallPolicyDecryptionProfile:NetworkFirewallPolicyDecryptionProfile", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering NetworkFirewallPolicyDecryptionProfile resources.
type networkFirewallPolicyDecryptionProfileState struct {
	// (Updatable) Whether to block sessions if the server's certificate uses extensions other than key usage and/or extended key usage.
	AreCertificateExtensionsRestricted *bool `pulumi:"areCertificateExtensionsRestricted"`
	// (Updatable) Whether to automatically append SAN to impersonating certificate if server certificate is missing SAN.
	IsAutoIncludeAltName *bool `pulumi:"isAutoIncludeAltName"`
	// (Updatable) Whether to block sessions if server's certificate is expired.
	IsExpiredCertificateBlocked *bool `pulumi:"isExpiredCertificateBlocked"`
	// (Updatable) Whether to block sessions if the firewall is temporarily unable to decrypt their traffic.
	IsOutOfCapacityBlocked *bool `pulumi:"isOutOfCapacityBlocked"`
	// (Updatable) Whether to block sessions if the revocation status check for server's certificate does not succeed within the maximum allowed time (defaulting to 5 seconds).
	IsRevocationStatusTimeoutBlocked *bool `pulumi:"isRevocationStatusTimeoutBlocked"`
	// (Updatable) Whether to block sessions if the revocation status check for server's certificate results in "unknown".
	IsUnknownRevocationStatusBlocked *bool `pulumi:"isUnknownRevocationStatusBlocked"`
	// (Updatable) Whether to block sessions if SSL cipher suite is not supported.
	IsUnsupportedCipherBlocked *bool `pulumi:"isUnsupportedCipherBlocked"`
	// (Updatable) Whether to block sessions if SSL version is not supported.
	IsUnsupportedVersionBlocked *bool `pulumi:"isUnsupportedVersionBlocked"`
	// (Updatable) Whether to block sessions if server's certificate is issued by an untrusted certificate authority (CA).
	IsUntrustedIssuerBlocked *bool `pulumi:"isUntrustedIssuerBlocked"`
	// Name of the decryption profile.
	Name *string `pulumi:"name"`
	// Unique Network Firewall Policy identifier
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	NetworkFirewallPolicyId *string `pulumi:"networkFirewallPolicyId"`
	// OCID of the Network Firewall Policy this decryption profile belongs to.
	ParentResourceId *string `pulumi:"parentResourceId"`
	// Describes the type of decryption profile. The accepted values are - * SSL_FORWARD_PROXY * SSL_INBOUND_INSPECTION
	Type *string `pulumi:"type"`
}

type NetworkFirewallPolicyDecryptionProfileState struct {
	// (Updatable) Whether to block sessions if the server's certificate uses extensions other than key usage and/or extended key usage.
	AreCertificateExtensionsRestricted pulumi.BoolPtrInput
	// (Updatable) Whether to automatically append SAN to impersonating certificate if server certificate is missing SAN.
	IsAutoIncludeAltName pulumi.BoolPtrInput
	// (Updatable) Whether to block sessions if server's certificate is expired.
	IsExpiredCertificateBlocked pulumi.BoolPtrInput
	// (Updatable) Whether to block sessions if the firewall is temporarily unable to decrypt their traffic.
	IsOutOfCapacityBlocked pulumi.BoolPtrInput
	// (Updatable) Whether to block sessions if the revocation status check for server's certificate does not succeed within the maximum allowed time (defaulting to 5 seconds).
	IsRevocationStatusTimeoutBlocked pulumi.BoolPtrInput
	// (Updatable) Whether to block sessions if the revocation status check for server's certificate results in "unknown".
	IsUnknownRevocationStatusBlocked pulumi.BoolPtrInput
	// (Updatable) Whether to block sessions if SSL cipher suite is not supported.
	IsUnsupportedCipherBlocked pulumi.BoolPtrInput
	// (Updatable) Whether to block sessions if SSL version is not supported.
	IsUnsupportedVersionBlocked pulumi.BoolPtrInput
	// (Updatable) Whether to block sessions if server's certificate is issued by an untrusted certificate authority (CA).
	IsUntrustedIssuerBlocked pulumi.BoolPtrInput
	// Name of the decryption profile.
	Name pulumi.StringPtrInput
	// Unique Network Firewall Policy identifier
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	NetworkFirewallPolicyId pulumi.StringPtrInput
	// OCID of the Network Firewall Policy this decryption profile belongs to.
	ParentResourceId pulumi.StringPtrInput
	// Describes the type of decryption profile. The accepted values are - * SSL_FORWARD_PROXY * SSL_INBOUND_INSPECTION
	Type pulumi.StringPtrInput
}

func (NetworkFirewallPolicyDecryptionProfileState) ElementType() reflect.Type {
	return reflect.TypeOf((*networkFirewallPolicyDecryptionProfileState)(nil)).Elem()
}

type networkFirewallPolicyDecryptionProfileArgs struct {
	// (Updatable) Whether to block sessions if the server's certificate uses extensions other than key usage and/or extended key usage.
	AreCertificateExtensionsRestricted *bool `pulumi:"areCertificateExtensionsRestricted"`
	// (Updatable) Whether to automatically append SAN to impersonating certificate if server certificate is missing SAN.
	IsAutoIncludeAltName *bool `pulumi:"isAutoIncludeAltName"`
	// (Updatable) Whether to block sessions if server's certificate is expired.
	IsExpiredCertificateBlocked *bool `pulumi:"isExpiredCertificateBlocked"`
	// (Updatable) Whether to block sessions if the firewall is temporarily unable to decrypt their traffic.
	IsOutOfCapacityBlocked *bool `pulumi:"isOutOfCapacityBlocked"`
	// (Updatable) Whether to block sessions if the revocation status check for server's certificate does not succeed within the maximum allowed time (defaulting to 5 seconds).
	IsRevocationStatusTimeoutBlocked *bool `pulumi:"isRevocationStatusTimeoutBlocked"`
	// (Updatable) Whether to block sessions if the revocation status check for server's certificate results in "unknown".
	IsUnknownRevocationStatusBlocked *bool `pulumi:"isUnknownRevocationStatusBlocked"`
	// (Updatable) Whether to block sessions if SSL cipher suite is not supported.
	IsUnsupportedCipherBlocked *bool `pulumi:"isUnsupportedCipherBlocked"`
	// (Updatable) Whether to block sessions if SSL version is not supported.
	IsUnsupportedVersionBlocked *bool `pulumi:"isUnsupportedVersionBlocked"`
	// (Updatable) Whether to block sessions if server's certificate is issued by an untrusted certificate authority (CA).
	IsUntrustedIssuerBlocked *bool `pulumi:"isUntrustedIssuerBlocked"`
	// Name of the decryption profile.
	Name *string `pulumi:"name"`
	// Unique Network Firewall Policy identifier
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	NetworkFirewallPolicyId string `pulumi:"networkFirewallPolicyId"`
	// Describes the type of decryption profile. The accepted values are - * SSL_FORWARD_PROXY * SSL_INBOUND_INSPECTION
	Type string `pulumi:"type"`
}

// The set of arguments for constructing a NetworkFirewallPolicyDecryptionProfile resource.
type NetworkFirewallPolicyDecryptionProfileArgs struct {
	// (Updatable) Whether to block sessions if the server's certificate uses extensions other than key usage and/or extended key usage.
	AreCertificateExtensionsRestricted pulumi.BoolPtrInput
	// (Updatable) Whether to automatically append SAN to impersonating certificate if server certificate is missing SAN.
	IsAutoIncludeAltName pulumi.BoolPtrInput
	// (Updatable) Whether to block sessions if server's certificate is expired.
	IsExpiredCertificateBlocked pulumi.BoolPtrInput
	// (Updatable) Whether to block sessions if the firewall is temporarily unable to decrypt their traffic.
	IsOutOfCapacityBlocked pulumi.BoolPtrInput
	// (Updatable) Whether to block sessions if the revocation status check for server's certificate does not succeed within the maximum allowed time (defaulting to 5 seconds).
	IsRevocationStatusTimeoutBlocked pulumi.BoolPtrInput
	// (Updatable) Whether to block sessions if the revocation status check for server's certificate results in "unknown".
	IsUnknownRevocationStatusBlocked pulumi.BoolPtrInput
	// (Updatable) Whether to block sessions if SSL cipher suite is not supported.
	IsUnsupportedCipherBlocked pulumi.BoolPtrInput
	// (Updatable) Whether to block sessions if SSL version is not supported.
	IsUnsupportedVersionBlocked pulumi.BoolPtrInput
	// (Updatable) Whether to block sessions if server's certificate is issued by an untrusted certificate authority (CA).
	IsUntrustedIssuerBlocked pulumi.BoolPtrInput
	// Name of the decryption profile.
	Name pulumi.StringPtrInput
	// Unique Network Firewall Policy identifier
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	NetworkFirewallPolicyId pulumi.StringInput
	// Describes the type of decryption profile. The accepted values are - * SSL_FORWARD_PROXY * SSL_INBOUND_INSPECTION
	Type pulumi.StringInput
}

func (NetworkFirewallPolicyDecryptionProfileArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*networkFirewallPolicyDecryptionProfileArgs)(nil)).Elem()
}

type NetworkFirewallPolicyDecryptionProfileInput interface {
	pulumi.Input

	ToNetworkFirewallPolicyDecryptionProfileOutput() NetworkFirewallPolicyDecryptionProfileOutput
	ToNetworkFirewallPolicyDecryptionProfileOutputWithContext(ctx context.Context) NetworkFirewallPolicyDecryptionProfileOutput
}

func (*NetworkFirewallPolicyDecryptionProfile) ElementType() reflect.Type {
	return reflect.TypeOf((**NetworkFirewallPolicyDecryptionProfile)(nil)).Elem()
}

func (i *NetworkFirewallPolicyDecryptionProfile) ToNetworkFirewallPolicyDecryptionProfileOutput() NetworkFirewallPolicyDecryptionProfileOutput {
	return i.ToNetworkFirewallPolicyDecryptionProfileOutputWithContext(context.Background())
}

func (i *NetworkFirewallPolicyDecryptionProfile) ToNetworkFirewallPolicyDecryptionProfileOutputWithContext(ctx context.Context) NetworkFirewallPolicyDecryptionProfileOutput {
	return pulumi.ToOutputWithContext(ctx, i).(NetworkFirewallPolicyDecryptionProfileOutput)
}

func (i *NetworkFirewallPolicyDecryptionProfile) ToOutput(ctx context.Context) pulumix.Output[*NetworkFirewallPolicyDecryptionProfile] {
	return pulumix.Output[*NetworkFirewallPolicyDecryptionProfile]{
		OutputState: i.ToNetworkFirewallPolicyDecryptionProfileOutputWithContext(ctx).OutputState,
	}
}

// NetworkFirewallPolicyDecryptionProfileArrayInput is an input type that accepts NetworkFirewallPolicyDecryptionProfileArray and NetworkFirewallPolicyDecryptionProfileArrayOutput values.
// You can construct a concrete instance of `NetworkFirewallPolicyDecryptionProfileArrayInput` via:
//
//	NetworkFirewallPolicyDecryptionProfileArray{ NetworkFirewallPolicyDecryptionProfileArgs{...} }
type NetworkFirewallPolicyDecryptionProfileArrayInput interface {
	pulumi.Input

	ToNetworkFirewallPolicyDecryptionProfileArrayOutput() NetworkFirewallPolicyDecryptionProfileArrayOutput
	ToNetworkFirewallPolicyDecryptionProfileArrayOutputWithContext(context.Context) NetworkFirewallPolicyDecryptionProfileArrayOutput
}

type NetworkFirewallPolicyDecryptionProfileArray []NetworkFirewallPolicyDecryptionProfileInput

func (NetworkFirewallPolicyDecryptionProfileArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*NetworkFirewallPolicyDecryptionProfile)(nil)).Elem()
}

func (i NetworkFirewallPolicyDecryptionProfileArray) ToNetworkFirewallPolicyDecryptionProfileArrayOutput() NetworkFirewallPolicyDecryptionProfileArrayOutput {
	return i.ToNetworkFirewallPolicyDecryptionProfileArrayOutputWithContext(context.Background())
}

func (i NetworkFirewallPolicyDecryptionProfileArray) ToNetworkFirewallPolicyDecryptionProfileArrayOutputWithContext(ctx context.Context) NetworkFirewallPolicyDecryptionProfileArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(NetworkFirewallPolicyDecryptionProfileArrayOutput)
}

func (i NetworkFirewallPolicyDecryptionProfileArray) ToOutput(ctx context.Context) pulumix.Output[[]*NetworkFirewallPolicyDecryptionProfile] {
	return pulumix.Output[[]*NetworkFirewallPolicyDecryptionProfile]{
		OutputState: i.ToNetworkFirewallPolicyDecryptionProfileArrayOutputWithContext(ctx).OutputState,
	}
}

// NetworkFirewallPolicyDecryptionProfileMapInput is an input type that accepts NetworkFirewallPolicyDecryptionProfileMap and NetworkFirewallPolicyDecryptionProfileMapOutput values.
// You can construct a concrete instance of `NetworkFirewallPolicyDecryptionProfileMapInput` via:
//
//	NetworkFirewallPolicyDecryptionProfileMap{ "key": NetworkFirewallPolicyDecryptionProfileArgs{...} }
type NetworkFirewallPolicyDecryptionProfileMapInput interface {
	pulumi.Input

	ToNetworkFirewallPolicyDecryptionProfileMapOutput() NetworkFirewallPolicyDecryptionProfileMapOutput
	ToNetworkFirewallPolicyDecryptionProfileMapOutputWithContext(context.Context) NetworkFirewallPolicyDecryptionProfileMapOutput
}

type NetworkFirewallPolicyDecryptionProfileMap map[string]NetworkFirewallPolicyDecryptionProfileInput

func (NetworkFirewallPolicyDecryptionProfileMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*NetworkFirewallPolicyDecryptionProfile)(nil)).Elem()
}

func (i NetworkFirewallPolicyDecryptionProfileMap) ToNetworkFirewallPolicyDecryptionProfileMapOutput() NetworkFirewallPolicyDecryptionProfileMapOutput {
	return i.ToNetworkFirewallPolicyDecryptionProfileMapOutputWithContext(context.Background())
}

func (i NetworkFirewallPolicyDecryptionProfileMap) ToNetworkFirewallPolicyDecryptionProfileMapOutputWithContext(ctx context.Context) NetworkFirewallPolicyDecryptionProfileMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(NetworkFirewallPolicyDecryptionProfileMapOutput)
}

func (i NetworkFirewallPolicyDecryptionProfileMap) ToOutput(ctx context.Context) pulumix.Output[map[string]*NetworkFirewallPolicyDecryptionProfile] {
	return pulumix.Output[map[string]*NetworkFirewallPolicyDecryptionProfile]{
		OutputState: i.ToNetworkFirewallPolicyDecryptionProfileMapOutputWithContext(ctx).OutputState,
	}
}

type NetworkFirewallPolicyDecryptionProfileOutput struct{ *pulumi.OutputState }

func (NetworkFirewallPolicyDecryptionProfileOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**NetworkFirewallPolicyDecryptionProfile)(nil)).Elem()
}

func (o NetworkFirewallPolicyDecryptionProfileOutput) ToNetworkFirewallPolicyDecryptionProfileOutput() NetworkFirewallPolicyDecryptionProfileOutput {
	return o
}

func (o NetworkFirewallPolicyDecryptionProfileOutput) ToNetworkFirewallPolicyDecryptionProfileOutputWithContext(ctx context.Context) NetworkFirewallPolicyDecryptionProfileOutput {
	return o
}

func (o NetworkFirewallPolicyDecryptionProfileOutput) ToOutput(ctx context.Context) pulumix.Output[*NetworkFirewallPolicyDecryptionProfile] {
	return pulumix.Output[*NetworkFirewallPolicyDecryptionProfile]{
		OutputState: o.OutputState,
	}
}

// (Updatable) Whether to block sessions if the server's certificate uses extensions other than key usage and/or extended key usage.
func (o NetworkFirewallPolicyDecryptionProfileOutput) AreCertificateExtensionsRestricted() pulumi.BoolOutput {
	return o.ApplyT(func(v *NetworkFirewallPolicyDecryptionProfile) pulumi.BoolOutput {
		return v.AreCertificateExtensionsRestricted
	}).(pulumi.BoolOutput)
}

// (Updatable) Whether to automatically append SAN to impersonating certificate if server certificate is missing SAN.
func (o NetworkFirewallPolicyDecryptionProfileOutput) IsAutoIncludeAltName() pulumi.BoolOutput {
	return o.ApplyT(func(v *NetworkFirewallPolicyDecryptionProfile) pulumi.BoolOutput { return v.IsAutoIncludeAltName }).(pulumi.BoolOutput)
}

// (Updatable) Whether to block sessions if server's certificate is expired.
func (o NetworkFirewallPolicyDecryptionProfileOutput) IsExpiredCertificateBlocked() pulumi.BoolOutput {
	return o.ApplyT(func(v *NetworkFirewallPolicyDecryptionProfile) pulumi.BoolOutput {
		return v.IsExpiredCertificateBlocked
	}).(pulumi.BoolOutput)
}

// (Updatable) Whether to block sessions if the firewall is temporarily unable to decrypt their traffic.
func (o NetworkFirewallPolicyDecryptionProfileOutput) IsOutOfCapacityBlocked() pulumi.BoolOutput {
	return o.ApplyT(func(v *NetworkFirewallPolicyDecryptionProfile) pulumi.BoolOutput { return v.IsOutOfCapacityBlocked }).(pulumi.BoolOutput)
}

// (Updatable) Whether to block sessions if the revocation status check for server's certificate does not succeed within the maximum allowed time (defaulting to 5 seconds).
func (o NetworkFirewallPolicyDecryptionProfileOutput) IsRevocationStatusTimeoutBlocked() pulumi.BoolOutput {
	return o.ApplyT(func(v *NetworkFirewallPolicyDecryptionProfile) pulumi.BoolOutput {
		return v.IsRevocationStatusTimeoutBlocked
	}).(pulumi.BoolOutput)
}

// (Updatable) Whether to block sessions if the revocation status check for server's certificate results in "unknown".
func (o NetworkFirewallPolicyDecryptionProfileOutput) IsUnknownRevocationStatusBlocked() pulumi.BoolOutput {
	return o.ApplyT(func(v *NetworkFirewallPolicyDecryptionProfile) pulumi.BoolOutput {
		return v.IsUnknownRevocationStatusBlocked
	}).(pulumi.BoolOutput)
}

// (Updatable) Whether to block sessions if SSL cipher suite is not supported.
func (o NetworkFirewallPolicyDecryptionProfileOutput) IsUnsupportedCipherBlocked() pulumi.BoolOutput {
	return o.ApplyT(func(v *NetworkFirewallPolicyDecryptionProfile) pulumi.BoolOutput { return v.IsUnsupportedCipherBlocked }).(pulumi.BoolOutput)
}

// (Updatable) Whether to block sessions if SSL version is not supported.
func (o NetworkFirewallPolicyDecryptionProfileOutput) IsUnsupportedVersionBlocked() pulumi.BoolOutput {
	return o.ApplyT(func(v *NetworkFirewallPolicyDecryptionProfile) pulumi.BoolOutput {
		return v.IsUnsupportedVersionBlocked
	}).(pulumi.BoolOutput)
}

// (Updatable) Whether to block sessions if server's certificate is issued by an untrusted certificate authority (CA).
func (o NetworkFirewallPolicyDecryptionProfileOutput) IsUntrustedIssuerBlocked() pulumi.BoolOutput {
	return o.ApplyT(func(v *NetworkFirewallPolicyDecryptionProfile) pulumi.BoolOutput { return v.IsUntrustedIssuerBlocked }).(pulumi.BoolOutput)
}

// Name of the decryption profile.
func (o NetworkFirewallPolicyDecryptionProfileOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *NetworkFirewallPolicyDecryptionProfile) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// Unique Network Firewall Policy identifier
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o NetworkFirewallPolicyDecryptionProfileOutput) NetworkFirewallPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v *NetworkFirewallPolicyDecryptionProfile) pulumi.StringOutput { return v.NetworkFirewallPolicyId }).(pulumi.StringOutput)
}

// OCID of the Network Firewall Policy this decryption profile belongs to.
func (o NetworkFirewallPolicyDecryptionProfileOutput) ParentResourceId() pulumi.StringOutput {
	return o.ApplyT(func(v *NetworkFirewallPolicyDecryptionProfile) pulumi.StringOutput { return v.ParentResourceId }).(pulumi.StringOutput)
}

// Describes the type of decryption profile. The accepted values are - * SSL_FORWARD_PROXY * SSL_INBOUND_INSPECTION
func (o NetworkFirewallPolicyDecryptionProfileOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v *NetworkFirewallPolicyDecryptionProfile) pulumi.StringOutput { return v.Type }).(pulumi.StringOutput)
}

type NetworkFirewallPolicyDecryptionProfileArrayOutput struct{ *pulumi.OutputState }

func (NetworkFirewallPolicyDecryptionProfileArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*NetworkFirewallPolicyDecryptionProfile)(nil)).Elem()
}

func (o NetworkFirewallPolicyDecryptionProfileArrayOutput) ToNetworkFirewallPolicyDecryptionProfileArrayOutput() NetworkFirewallPolicyDecryptionProfileArrayOutput {
	return o
}

func (o NetworkFirewallPolicyDecryptionProfileArrayOutput) ToNetworkFirewallPolicyDecryptionProfileArrayOutputWithContext(ctx context.Context) NetworkFirewallPolicyDecryptionProfileArrayOutput {
	return o
}

func (o NetworkFirewallPolicyDecryptionProfileArrayOutput) ToOutput(ctx context.Context) pulumix.Output[[]*NetworkFirewallPolicyDecryptionProfile] {
	return pulumix.Output[[]*NetworkFirewallPolicyDecryptionProfile]{
		OutputState: o.OutputState,
	}
}

func (o NetworkFirewallPolicyDecryptionProfileArrayOutput) Index(i pulumi.IntInput) NetworkFirewallPolicyDecryptionProfileOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *NetworkFirewallPolicyDecryptionProfile {
		return vs[0].([]*NetworkFirewallPolicyDecryptionProfile)[vs[1].(int)]
	}).(NetworkFirewallPolicyDecryptionProfileOutput)
}

type NetworkFirewallPolicyDecryptionProfileMapOutput struct{ *pulumi.OutputState }

func (NetworkFirewallPolicyDecryptionProfileMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*NetworkFirewallPolicyDecryptionProfile)(nil)).Elem()
}

func (o NetworkFirewallPolicyDecryptionProfileMapOutput) ToNetworkFirewallPolicyDecryptionProfileMapOutput() NetworkFirewallPolicyDecryptionProfileMapOutput {
	return o
}

func (o NetworkFirewallPolicyDecryptionProfileMapOutput) ToNetworkFirewallPolicyDecryptionProfileMapOutputWithContext(ctx context.Context) NetworkFirewallPolicyDecryptionProfileMapOutput {
	return o
}

func (o NetworkFirewallPolicyDecryptionProfileMapOutput) ToOutput(ctx context.Context) pulumix.Output[map[string]*NetworkFirewallPolicyDecryptionProfile] {
	return pulumix.Output[map[string]*NetworkFirewallPolicyDecryptionProfile]{
		OutputState: o.OutputState,
	}
}

func (o NetworkFirewallPolicyDecryptionProfileMapOutput) MapIndex(k pulumi.StringInput) NetworkFirewallPolicyDecryptionProfileOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *NetworkFirewallPolicyDecryptionProfile {
		return vs[0].(map[string]*NetworkFirewallPolicyDecryptionProfile)[vs[1].(string)]
	}).(NetworkFirewallPolicyDecryptionProfileOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*NetworkFirewallPolicyDecryptionProfileInput)(nil)).Elem(), &NetworkFirewallPolicyDecryptionProfile{})
	pulumi.RegisterInputType(reflect.TypeOf((*NetworkFirewallPolicyDecryptionProfileArrayInput)(nil)).Elem(), NetworkFirewallPolicyDecryptionProfileArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*NetworkFirewallPolicyDecryptionProfileMapInput)(nil)).Elem(), NetworkFirewallPolicyDecryptionProfileMap{})
	pulumi.RegisterOutputType(NetworkFirewallPolicyDecryptionProfileOutput{})
	pulumi.RegisterOutputType(NetworkFirewallPolicyDecryptionProfileArrayOutput{})
	pulumi.RegisterOutputType(NetworkFirewallPolicyDecryptionProfileMapOutput{})
}