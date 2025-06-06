// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package kms

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Key Version resource in Oracle Cloud Infrastructure Kms service.
//
// Generates a new [KeyVersion](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/KeyVersion/) resource that provides new cryptographic
// material for a master encryption key. The key must be in an `ENABLED` state to be rotated.
//
// As a management operation, this call is subject to a Key Management limit that applies to the total number
// of requests across all  management write operations. Key Management might throttle this call to reject an
// otherwise valid request when the total rate of management write operations exceeds 10 requests per second
// for a given tenancy.
//
// ## Import
//
// KeyVersions can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Kms/keyVersion:KeyVersion test_key_version "managementEndpoint/{managementEndpoint}/keys/{keyId}/keyVersions/{keyVersionId}"
// ```
type KeyVersion struct {
	pulumi.CustomResourceState

	// The OCID of the compartment that contains this key version.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// Key reference data to be returned to the customer as a response.
	ExternalKeyReferenceDetails KeyVersionExternalKeyReferenceDetailArrayOutput `pulumi:"externalKeyReferenceDetails"`
	// Key version ID associated with the external key.
	ExternalKeyVersionId pulumi.StringOutput `pulumi:"externalKeyVersionId"`
	// An optional property indicating whether this keyversion is generated from auto rotatation.
	IsAutoRotated pulumi.BoolOutput `pulumi:"isAutoRotated"`
	// A Boolean value that indicates whether the KeyVersion belongs to primary Vault or replica Vault.
	IsPrimary pulumi.BoolOutput `pulumi:"isPrimary"`
	// The OCID of the key.
	KeyId        pulumi.StringOutput `pulumi:"keyId"`
	KeyVersionId pulumi.StringOutput `pulumi:"keyVersionId"`
	// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
	ManagementEndpoint pulumi.StringOutput `pulumi:"managementEndpoint"`
	// The public key in PEM format. (This value pertains only to RSA and ECDSA keys.)
	PublicKey pulumi.StringOutput `pulumi:"publicKey"`
	// KeyVersion replica details
	ReplicaDetails    KeyVersionReplicaDetailArrayOutput `pulumi:"replicaDetails"`
	RestoredFromKeyId pulumi.StringOutput                `pulumi:"restoredFromKeyId"`
	// The OCID of the key version from which this key version was restored.
	RestoredFromKeyVersionId pulumi.StringOutput `pulumi:"restoredFromKeyVersionId"`
	// The key version's current lifecycle state.  Example: `ENABLED`
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time this key version was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: "2018-04-03T21:10:29.600Z"
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// (Updatable) An optional property for the deletion time of the key version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TimeOfDeletion pulumi.StringOutput `pulumi:"timeOfDeletion"`
	// The OCID of the vault that contains this key version.
	VaultId pulumi.StringOutput `pulumi:"vaultId"`
}

// NewKeyVersion registers a new resource with the given unique name, arguments, and options.
func NewKeyVersion(ctx *pulumi.Context,
	name string, args *KeyVersionArgs, opts ...pulumi.ResourceOption) (*KeyVersion, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.KeyId == nil {
		return nil, errors.New("invalid value for required argument 'KeyId'")
	}
	if args.ManagementEndpoint == nil {
		return nil, errors.New("invalid value for required argument 'ManagementEndpoint'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource KeyVersion
	err := ctx.RegisterResource("oci:Kms/keyVersion:KeyVersion", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetKeyVersion gets an existing KeyVersion resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetKeyVersion(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *KeyVersionState, opts ...pulumi.ResourceOption) (*KeyVersion, error) {
	var resource KeyVersion
	err := ctx.ReadResource("oci:Kms/keyVersion:KeyVersion", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering KeyVersion resources.
type keyVersionState struct {
	// The OCID of the compartment that contains this key version.
	CompartmentId *string `pulumi:"compartmentId"`
	// Key reference data to be returned to the customer as a response.
	ExternalKeyReferenceDetails []KeyVersionExternalKeyReferenceDetail `pulumi:"externalKeyReferenceDetails"`
	// Key version ID associated with the external key.
	ExternalKeyVersionId *string `pulumi:"externalKeyVersionId"`
	// An optional property indicating whether this keyversion is generated from auto rotatation.
	IsAutoRotated *bool `pulumi:"isAutoRotated"`
	// A Boolean value that indicates whether the KeyVersion belongs to primary Vault or replica Vault.
	IsPrimary *bool `pulumi:"isPrimary"`
	// The OCID of the key.
	KeyId        *string `pulumi:"keyId"`
	KeyVersionId *string `pulumi:"keyVersionId"`
	// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
	ManagementEndpoint *string `pulumi:"managementEndpoint"`
	// The public key in PEM format. (This value pertains only to RSA and ECDSA keys.)
	PublicKey *string `pulumi:"publicKey"`
	// KeyVersion replica details
	ReplicaDetails    []KeyVersionReplicaDetail `pulumi:"replicaDetails"`
	RestoredFromKeyId *string                   `pulumi:"restoredFromKeyId"`
	// The OCID of the key version from which this key version was restored.
	RestoredFromKeyVersionId *string `pulumi:"restoredFromKeyVersionId"`
	// The key version's current lifecycle state.  Example: `ENABLED`
	State *string `pulumi:"state"`
	// The date and time this key version was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: "2018-04-03T21:10:29.600Z"
	TimeCreated *string `pulumi:"timeCreated"`
	// (Updatable) An optional property for the deletion time of the key version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TimeOfDeletion *string `pulumi:"timeOfDeletion"`
	// The OCID of the vault that contains this key version.
	VaultId *string `pulumi:"vaultId"`
}

type KeyVersionState struct {
	// The OCID of the compartment that contains this key version.
	CompartmentId pulumi.StringPtrInput
	// Key reference data to be returned to the customer as a response.
	ExternalKeyReferenceDetails KeyVersionExternalKeyReferenceDetailArrayInput
	// Key version ID associated with the external key.
	ExternalKeyVersionId pulumi.StringPtrInput
	// An optional property indicating whether this keyversion is generated from auto rotatation.
	IsAutoRotated pulumi.BoolPtrInput
	// A Boolean value that indicates whether the KeyVersion belongs to primary Vault or replica Vault.
	IsPrimary pulumi.BoolPtrInput
	// The OCID of the key.
	KeyId        pulumi.StringPtrInput
	KeyVersionId pulumi.StringPtrInput
	// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
	ManagementEndpoint pulumi.StringPtrInput
	// The public key in PEM format. (This value pertains only to RSA and ECDSA keys.)
	PublicKey pulumi.StringPtrInput
	// KeyVersion replica details
	ReplicaDetails    KeyVersionReplicaDetailArrayInput
	RestoredFromKeyId pulumi.StringPtrInput
	// The OCID of the key version from which this key version was restored.
	RestoredFromKeyVersionId pulumi.StringPtrInput
	// The key version's current lifecycle state.  Example: `ENABLED`
	State pulumi.StringPtrInput
	// The date and time this key version was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: "2018-04-03T21:10:29.600Z"
	TimeCreated pulumi.StringPtrInput
	// (Updatable) An optional property for the deletion time of the key version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TimeOfDeletion pulumi.StringPtrInput
	// The OCID of the vault that contains this key version.
	VaultId pulumi.StringPtrInput
}

func (KeyVersionState) ElementType() reflect.Type {
	return reflect.TypeOf((*keyVersionState)(nil)).Elem()
}

type keyVersionArgs struct {
	// Key version ID associated with the external key.
	ExternalKeyVersionId *string `pulumi:"externalKeyVersionId"`
	// The OCID of the key.
	KeyId string `pulumi:"keyId"`
	// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
	ManagementEndpoint string `pulumi:"managementEndpoint"`
	// (Updatable) An optional property for the deletion time of the key version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TimeOfDeletion *string `pulumi:"timeOfDeletion"`
}

// The set of arguments for constructing a KeyVersion resource.
type KeyVersionArgs struct {
	// Key version ID associated with the external key.
	ExternalKeyVersionId pulumi.StringPtrInput
	// The OCID of the key.
	KeyId pulumi.StringInput
	// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
	ManagementEndpoint pulumi.StringInput
	// (Updatable) An optional property for the deletion time of the key version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TimeOfDeletion pulumi.StringPtrInput
}

func (KeyVersionArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*keyVersionArgs)(nil)).Elem()
}

type KeyVersionInput interface {
	pulumi.Input

	ToKeyVersionOutput() KeyVersionOutput
	ToKeyVersionOutputWithContext(ctx context.Context) KeyVersionOutput
}

func (*KeyVersion) ElementType() reflect.Type {
	return reflect.TypeOf((**KeyVersion)(nil)).Elem()
}

func (i *KeyVersion) ToKeyVersionOutput() KeyVersionOutput {
	return i.ToKeyVersionOutputWithContext(context.Background())
}

func (i *KeyVersion) ToKeyVersionOutputWithContext(ctx context.Context) KeyVersionOutput {
	return pulumi.ToOutputWithContext(ctx, i).(KeyVersionOutput)
}

// KeyVersionArrayInput is an input type that accepts KeyVersionArray and KeyVersionArrayOutput values.
// You can construct a concrete instance of `KeyVersionArrayInput` via:
//
//	KeyVersionArray{ KeyVersionArgs{...} }
type KeyVersionArrayInput interface {
	pulumi.Input

	ToKeyVersionArrayOutput() KeyVersionArrayOutput
	ToKeyVersionArrayOutputWithContext(context.Context) KeyVersionArrayOutput
}

type KeyVersionArray []KeyVersionInput

func (KeyVersionArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*KeyVersion)(nil)).Elem()
}

func (i KeyVersionArray) ToKeyVersionArrayOutput() KeyVersionArrayOutput {
	return i.ToKeyVersionArrayOutputWithContext(context.Background())
}

func (i KeyVersionArray) ToKeyVersionArrayOutputWithContext(ctx context.Context) KeyVersionArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(KeyVersionArrayOutput)
}

// KeyVersionMapInput is an input type that accepts KeyVersionMap and KeyVersionMapOutput values.
// You can construct a concrete instance of `KeyVersionMapInput` via:
//
//	KeyVersionMap{ "key": KeyVersionArgs{...} }
type KeyVersionMapInput interface {
	pulumi.Input

	ToKeyVersionMapOutput() KeyVersionMapOutput
	ToKeyVersionMapOutputWithContext(context.Context) KeyVersionMapOutput
}

type KeyVersionMap map[string]KeyVersionInput

func (KeyVersionMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*KeyVersion)(nil)).Elem()
}

func (i KeyVersionMap) ToKeyVersionMapOutput() KeyVersionMapOutput {
	return i.ToKeyVersionMapOutputWithContext(context.Background())
}

func (i KeyVersionMap) ToKeyVersionMapOutputWithContext(ctx context.Context) KeyVersionMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(KeyVersionMapOutput)
}

type KeyVersionOutput struct{ *pulumi.OutputState }

func (KeyVersionOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**KeyVersion)(nil)).Elem()
}

func (o KeyVersionOutput) ToKeyVersionOutput() KeyVersionOutput {
	return o
}

func (o KeyVersionOutput) ToKeyVersionOutputWithContext(ctx context.Context) KeyVersionOutput {
	return o
}

// The OCID of the compartment that contains this key version.
func (o KeyVersionOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *KeyVersion) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// Key reference data to be returned to the customer as a response.
func (o KeyVersionOutput) ExternalKeyReferenceDetails() KeyVersionExternalKeyReferenceDetailArrayOutput {
	return o.ApplyT(func(v *KeyVersion) KeyVersionExternalKeyReferenceDetailArrayOutput {
		return v.ExternalKeyReferenceDetails
	}).(KeyVersionExternalKeyReferenceDetailArrayOutput)
}

// Key version ID associated with the external key.
func (o KeyVersionOutput) ExternalKeyVersionId() pulumi.StringOutput {
	return o.ApplyT(func(v *KeyVersion) pulumi.StringOutput { return v.ExternalKeyVersionId }).(pulumi.StringOutput)
}

// An optional property indicating whether this keyversion is generated from auto rotatation.
func (o KeyVersionOutput) IsAutoRotated() pulumi.BoolOutput {
	return o.ApplyT(func(v *KeyVersion) pulumi.BoolOutput { return v.IsAutoRotated }).(pulumi.BoolOutput)
}

// A Boolean value that indicates whether the KeyVersion belongs to primary Vault or replica Vault.
func (o KeyVersionOutput) IsPrimary() pulumi.BoolOutput {
	return o.ApplyT(func(v *KeyVersion) pulumi.BoolOutput { return v.IsPrimary }).(pulumi.BoolOutput)
}

// The OCID of the key.
func (o KeyVersionOutput) KeyId() pulumi.StringOutput {
	return o.ApplyT(func(v *KeyVersion) pulumi.StringOutput { return v.KeyId }).(pulumi.StringOutput)
}

func (o KeyVersionOutput) KeyVersionId() pulumi.StringOutput {
	return o.ApplyT(func(v *KeyVersion) pulumi.StringOutput { return v.KeyVersionId }).(pulumi.StringOutput)
}

// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
func (o KeyVersionOutput) ManagementEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v *KeyVersion) pulumi.StringOutput { return v.ManagementEndpoint }).(pulumi.StringOutput)
}

// The public key in PEM format. (This value pertains only to RSA and ECDSA keys.)
func (o KeyVersionOutput) PublicKey() pulumi.StringOutput {
	return o.ApplyT(func(v *KeyVersion) pulumi.StringOutput { return v.PublicKey }).(pulumi.StringOutput)
}

// KeyVersion replica details
func (o KeyVersionOutput) ReplicaDetails() KeyVersionReplicaDetailArrayOutput {
	return o.ApplyT(func(v *KeyVersion) KeyVersionReplicaDetailArrayOutput { return v.ReplicaDetails }).(KeyVersionReplicaDetailArrayOutput)
}

func (o KeyVersionOutput) RestoredFromKeyId() pulumi.StringOutput {
	return o.ApplyT(func(v *KeyVersion) pulumi.StringOutput { return v.RestoredFromKeyId }).(pulumi.StringOutput)
}

// The OCID of the key version from which this key version was restored.
func (o KeyVersionOutput) RestoredFromKeyVersionId() pulumi.StringOutput {
	return o.ApplyT(func(v *KeyVersion) pulumi.StringOutput { return v.RestoredFromKeyVersionId }).(pulumi.StringOutput)
}

// The key version's current lifecycle state.  Example: `ENABLED`
func (o KeyVersionOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *KeyVersion) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time this key version was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: "2018-04-03T21:10:29.600Z"
func (o KeyVersionOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *KeyVersion) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// (Updatable) An optional property for the deletion time of the key version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o KeyVersionOutput) TimeOfDeletion() pulumi.StringOutput {
	return o.ApplyT(func(v *KeyVersion) pulumi.StringOutput { return v.TimeOfDeletion }).(pulumi.StringOutput)
}

// The OCID of the vault that contains this key version.
func (o KeyVersionOutput) VaultId() pulumi.StringOutput {
	return o.ApplyT(func(v *KeyVersion) pulumi.StringOutput { return v.VaultId }).(pulumi.StringOutput)
}

type KeyVersionArrayOutput struct{ *pulumi.OutputState }

func (KeyVersionArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*KeyVersion)(nil)).Elem()
}

func (o KeyVersionArrayOutput) ToKeyVersionArrayOutput() KeyVersionArrayOutput {
	return o
}

func (o KeyVersionArrayOutput) ToKeyVersionArrayOutputWithContext(ctx context.Context) KeyVersionArrayOutput {
	return o
}

func (o KeyVersionArrayOutput) Index(i pulumi.IntInput) KeyVersionOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *KeyVersion {
		return vs[0].([]*KeyVersion)[vs[1].(int)]
	}).(KeyVersionOutput)
}

type KeyVersionMapOutput struct{ *pulumi.OutputState }

func (KeyVersionMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*KeyVersion)(nil)).Elem()
}

func (o KeyVersionMapOutput) ToKeyVersionMapOutput() KeyVersionMapOutput {
	return o
}

func (o KeyVersionMapOutput) ToKeyVersionMapOutputWithContext(ctx context.Context) KeyVersionMapOutput {
	return o
}

func (o KeyVersionMapOutput) MapIndex(k pulumi.StringInput) KeyVersionOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *KeyVersion {
		return vs[0].(map[string]*KeyVersion)[vs[1].(string)]
	}).(KeyVersionOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*KeyVersionInput)(nil)).Elem(), &KeyVersion{})
	pulumi.RegisterInputType(reflect.TypeOf((*KeyVersionArrayInput)(nil)).Elem(), KeyVersionArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*KeyVersionMapInput)(nil)).Elem(), KeyVersionMap{})
	pulumi.RegisterOutputType(KeyVersionOutput{})
	pulumi.RegisterOutputType(KeyVersionArrayOutput{})
	pulumi.RegisterOutputType(KeyVersionMapOutput{})
}
