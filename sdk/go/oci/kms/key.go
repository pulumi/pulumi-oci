// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package kms

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Key resource in Oracle Cloud Infrastructure Kms service.
//
// Creates a new master encryption key.
//
// As a management operation, this call is subject to a Key Management limit that applies to the total
// number of requests across all management write operations. Key Management might throttle this call
// to reject an otherwise valid request when the total rate of management write operations exceeds 10
// requests per second for a given tenancy.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Kms"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Kms.NewKey(ctx, "testKey", &Kms.KeyArgs{
//				CompartmentId: pulumi.Any(_var.Compartment_id),
//				DisplayName:   pulumi.Any(_var.Key_display_name),
//				KeyShape: &kms.KeyKeyShapeArgs{
//					Algorithm: pulumi.Any(_var.Key_key_shape_algorithm),
//					Length:    pulumi.Any(_var.Key_key_shape_length),
//					CurveId:   pulumi.Any(oci_kms_curve.Test_curve.Id),
//				},
//				ManagementEndpoint: pulumi.Any(_var.Key_management_endpoint),
//				DefinedTags: pulumi.AnyMap{
//					"Operations.CostCenter": pulumi.Any("42"),
//				},
//				FreeformTags: pulumi.AnyMap{
//					"Department": pulumi.Any("Finance"),
//				},
//				ProtectionMode: pulumi.Any(_var.Key_protection_mode),
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
// Keys can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:Kms/key:Key test_key "managementEndpoint/{managementEndpoint}/keys/{keyId}"
//
// ```
type Key struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the compartment where you want to create the master encryption key.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// The OCID of the key version used in cryptographic operations. During key rotation, the service might be in a transitional state where this or a newer key version are used intermittently. The `currentKeyVersion` property is updated when the service is guaranteed to use the new key version for all subsequent encryption operations.
	CurrentKeyVersion pulumi.StringOutput `pulumi:"currentKeyVersion"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) Desired state of the key. Possible values : `ENABLED` or `DISABLED`
	DesiredState pulumi.StringOutput `pulumi:"desiredState"`
	// (Updatable) A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// A boolean that will be true when key is primary, and will be false when key is a replica from a primary key.
	IsPrimary pulumi.BoolOutput `pulumi:"isPrimary"`
	// The cryptographic properties of a key.
	KeyShape KeyKeyShapeOutput `pulumi:"keyShape"`
	// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
	ManagementEndpoint pulumi.StringOutput `pulumi:"managementEndpoint"`
	// The key's protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault's RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key's protection mode is set to `HSM`. You can't change a key's protection mode after the key is created or imported.
	ProtectionMode pulumi.StringOutput `pulumi:"protectionMode"`
	// Key replica details
	ReplicaDetails KeyReplicaDetailArrayOutput `pulumi:"replicaDetails"`
	// (Updatable) Details where key was backed up.
	RestoreFromFile KeyRestoreFromFilePtrOutput `pulumi:"restoreFromFile"`
	// (Updatable) Details where key was backed up
	RestoreFromObjectStore KeyRestoreFromObjectStorePtrOutput `pulumi:"restoreFromObjectStore"`
	// (Updatable) An optional property when flipped triggers restore from restore option provided in config file.
	RestoreTrigger pulumi.BoolPtrOutput `pulumi:"restoreTrigger"`
	// The OCID of the key from which this key was restored.
	RestoredFromKeyId pulumi.StringOutput `pulumi:"restoredFromKeyId"`
	// The key's current lifecycle state.  Example: `ENABLED`
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the key was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-04-03T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// (Updatable) An optional property for the deletion time of the key, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfDeletion pulumi.StringOutput `pulumi:"timeOfDeletion"`
	// The OCID of the vault that contains this key.
	VaultId pulumi.StringOutput `pulumi:"vaultId"`
}

// NewKey registers a new resource with the given unique name, arguments, and options.
func NewKey(ctx *pulumi.Context,
	name string, args *KeyArgs, opts ...pulumi.ResourceOption) (*Key, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.KeyShape == nil {
		return nil, errors.New("invalid value for required argument 'KeyShape'")
	}
	if args.ManagementEndpoint == nil {
		return nil, errors.New("invalid value for required argument 'ManagementEndpoint'")
	}
	var resource Key
	err := ctx.RegisterResource("oci:Kms/key:Key", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetKey gets an existing Key resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetKey(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *KeyState, opts ...pulumi.ResourceOption) (*Key, error) {
	var resource Key
	err := ctx.ReadResource("oci:Kms/key:Key", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Key resources.
type keyState struct {
	// (Updatable) The OCID of the compartment where you want to create the master encryption key.
	CompartmentId *string `pulumi:"compartmentId"`
	// The OCID of the key version used in cryptographic operations. During key rotation, the service might be in a transitional state where this or a newer key version are used intermittently. The `currentKeyVersion` property is updated when the service is guaranteed to use the new key version for all subsequent encryption operations.
	CurrentKeyVersion *string `pulumi:"currentKeyVersion"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Desired state of the key. Possible values : `ENABLED` or `DISABLED`
	DesiredState *string `pulumi:"desiredState"`
	// (Updatable) A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A boolean that will be true when key is primary, and will be false when key is a replica from a primary key.
	IsPrimary *bool `pulumi:"isPrimary"`
	// The cryptographic properties of a key.
	KeyShape *KeyKeyShape `pulumi:"keyShape"`
	// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
	ManagementEndpoint *string `pulumi:"managementEndpoint"`
	// The key's protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault's RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key's protection mode is set to `HSM`. You can't change a key's protection mode after the key is created or imported.
	ProtectionMode *string `pulumi:"protectionMode"`
	// Key replica details
	ReplicaDetails []KeyReplicaDetail `pulumi:"replicaDetails"`
	// (Updatable) Details where key was backed up.
	RestoreFromFile *KeyRestoreFromFile `pulumi:"restoreFromFile"`
	// (Updatable) Details where key was backed up
	RestoreFromObjectStore *KeyRestoreFromObjectStore `pulumi:"restoreFromObjectStore"`
	// (Updatable) An optional property when flipped triggers restore from restore option provided in config file.
	RestoreTrigger *bool `pulumi:"restoreTrigger"`
	// The OCID of the key from which this key was restored.
	RestoredFromKeyId *string `pulumi:"restoredFromKeyId"`
	// The key's current lifecycle state.  Example: `ENABLED`
	State *string `pulumi:"state"`
	// The date and time the key was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-04-03T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// (Updatable) An optional property for the deletion time of the key, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfDeletion *string `pulumi:"timeOfDeletion"`
	// The OCID of the vault that contains this key.
	VaultId *string `pulumi:"vaultId"`
}

type KeyState struct {
	// (Updatable) The OCID of the compartment where you want to create the master encryption key.
	CompartmentId pulumi.StringPtrInput
	// The OCID of the key version used in cryptographic operations. During key rotation, the service might be in a transitional state where this or a newer key version are used intermittently. The `currentKeyVersion` property is updated when the service is guaranteed to use the new key version for all subsequent encryption operations.
	CurrentKeyVersion pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Desired state of the key. Possible values : `ENABLED` or `DISABLED`
	DesiredState pulumi.StringPtrInput
	// (Updatable) A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// A boolean that will be true when key is primary, and will be false when key is a replica from a primary key.
	IsPrimary pulumi.BoolPtrInput
	// The cryptographic properties of a key.
	KeyShape KeyKeyShapePtrInput
	// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
	ManagementEndpoint pulumi.StringPtrInput
	// The key's protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault's RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key's protection mode is set to `HSM`. You can't change a key's protection mode after the key is created or imported.
	ProtectionMode pulumi.StringPtrInput
	// Key replica details
	ReplicaDetails KeyReplicaDetailArrayInput
	// (Updatable) Details where key was backed up.
	RestoreFromFile KeyRestoreFromFilePtrInput
	// (Updatable) Details where key was backed up
	RestoreFromObjectStore KeyRestoreFromObjectStorePtrInput
	// (Updatable) An optional property when flipped triggers restore from restore option provided in config file.
	RestoreTrigger pulumi.BoolPtrInput
	// The OCID of the key from which this key was restored.
	RestoredFromKeyId pulumi.StringPtrInput
	// The key's current lifecycle state.  Example: `ENABLED`
	State pulumi.StringPtrInput
	// The date and time the key was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-04-03T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// (Updatable) An optional property for the deletion time of the key, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfDeletion pulumi.StringPtrInput
	// The OCID of the vault that contains this key.
	VaultId pulumi.StringPtrInput
}

func (KeyState) ElementType() reflect.Type {
	return reflect.TypeOf((*keyState)(nil)).Elem()
}

type keyArgs struct {
	// (Updatable) The OCID of the compartment where you want to create the master encryption key.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Desired state of the key. Possible values : `ENABLED` or `DISABLED`
	DesiredState *string `pulumi:"desiredState"`
	// (Updatable) A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The cryptographic properties of a key.
	KeyShape KeyKeyShape `pulumi:"keyShape"`
	// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
	ManagementEndpoint string `pulumi:"managementEndpoint"`
	// The key's protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault's RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key's protection mode is set to `HSM`. You can't change a key's protection mode after the key is created or imported.
	ProtectionMode *string `pulumi:"protectionMode"`
	// (Updatable) Details where key was backed up.
	RestoreFromFile *KeyRestoreFromFile `pulumi:"restoreFromFile"`
	// (Updatable) Details where key was backed up
	RestoreFromObjectStore *KeyRestoreFromObjectStore `pulumi:"restoreFromObjectStore"`
	// (Updatable) An optional property when flipped triggers restore from restore option provided in config file.
	RestoreTrigger *bool `pulumi:"restoreTrigger"`
	// (Updatable) An optional property for the deletion time of the key, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfDeletion *string `pulumi:"timeOfDeletion"`
}

// The set of arguments for constructing a Key resource.
type KeyArgs struct {
	// (Updatable) The OCID of the compartment where you want to create the master encryption key.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Desired state of the key. Possible values : `ENABLED` or `DISABLED`
	DesiredState pulumi.StringPtrInput
	// (Updatable) A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The cryptographic properties of a key.
	KeyShape KeyKeyShapeInput
	// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
	ManagementEndpoint pulumi.StringInput
	// The key's protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault's RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key's protection mode is set to `HSM`. You can't change a key's protection mode after the key is created or imported.
	ProtectionMode pulumi.StringPtrInput
	// (Updatable) Details where key was backed up.
	RestoreFromFile KeyRestoreFromFilePtrInput
	// (Updatable) Details where key was backed up
	RestoreFromObjectStore KeyRestoreFromObjectStorePtrInput
	// (Updatable) An optional property when flipped triggers restore from restore option provided in config file.
	RestoreTrigger pulumi.BoolPtrInput
	// (Updatable) An optional property for the deletion time of the key, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfDeletion pulumi.StringPtrInput
}

func (KeyArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*keyArgs)(nil)).Elem()
}

type KeyInput interface {
	pulumi.Input

	ToKeyOutput() KeyOutput
	ToKeyOutputWithContext(ctx context.Context) KeyOutput
}

func (*Key) ElementType() reflect.Type {
	return reflect.TypeOf((**Key)(nil)).Elem()
}

func (i *Key) ToKeyOutput() KeyOutput {
	return i.ToKeyOutputWithContext(context.Background())
}

func (i *Key) ToKeyOutputWithContext(ctx context.Context) KeyOutput {
	return pulumi.ToOutputWithContext(ctx, i).(KeyOutput)
}

// KeyArrayInput is an input type that accepts KeyArray and KeyArrayOutput values.
// You can construct a concrete instance of `KeyArrayInput` via:
//
//	KeyArray{ KeyArgs{...} }
type KeyArrayInput interface {
	pulumi.Input

	ToKeyArrayOutput() KeyArrayOutput
	ToKeyArrayOutputWithContext(context.Context) KeyArrayOutput
}

type KeyArray []KeyInput

func (KeyArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Key)(nil)).Elem()
}

func (i KeyArray) ToKeyArrayOutput() KeyArrayOutput {
	return i.ToKeyArrayOutputWithContext(context.Background())
}

func (i KeyArray) ToKeyArrayOutputWithContext(ctx context.Context) KeyArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(KeyArrayOutput)
}

// KeyMapInput is an input type that accepts KeyMap and KeyMapOutput values.
// You can construct a concrete instance of `KeyMapInput` via:
//
//	KeyMap{ "key": KeyArgs{...} }
type KeyMapInput interface {
	pulumi.Input

	ToKeyMapOutput() KeyMapOutput
	ToKeyMapOutputWithContext(context.Context) KeyMapOutput
}

type KeyMap map[string]KeyInput

func (KeyMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Key)(nil)).Elem()
}

func (i KeyMap) ToKeyMapOutput() KeyMapOutput {
	return i.ToKeyMapOutputWithContext(context.Background())
}

func (i KeyMap) ToKeyMapOutputWithContext(ctx context.Context) KeyMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(KeyMapOutput)
}

type KeyOutput struct{ *pulumi.OutputState }

func (KeyOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Key)(nil)).Elem()
}

func (o KeyOutput) ToKeyOutput() KeyOutput {
	return o
}

func (o KeyOutput) ToKeyOutputWithContext(ctx context.Context) KeyOutput {
	return o
}

// (Updatable) The OCID of the compartment where you want to create the master encryption key.
func (o KeyOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Key) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// The OCID of the key version used in cryptographic operations. During key rotation, the service might be in a transitional state where this or a newer key version are used intermittently. The `currentKeyVersion` property is updated when the service is guaranteed to use the new key version for all subsequent encryption operations.
func (o KeyOutput) CurrentKeyVersion() pulumi.StringOutput {
	return o.ApplyT(func(v *Key) pulumi.StringOutput { return v.CurrentKeyVersion }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o KeyOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Key) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) Desired state of the key. Possible values : `ENABLED` or `DISABLED`
func (o KeyOutput) DesiredState() pulumi.StringOutput {
	return o.ApplyT(func(v *Key) pulumi.StringOutput { return v.DesiredState }).(pulumi.StringOutput)
}

// (Updatable) A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
func (o KeyOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *Key) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o KeyOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Key) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// A boolean that will be true when key is primary, and will be false when key is a replica from a primary key.
func (o KeyOutput) IsPrimary() pulumi.BoolOutput {
	return o.ApplyT(func(v *Key) pulumi.BoolOutput { return v.IsPrimary }).(pulumi.BoolOutput)
}

// The cryptographic properties of a key.
func (o KeyOutput) KeyShape() KeyKeyShapeOutput {
	return o.ApplyT(func(v *Key) KeyKeyShapeOutput { return v.KeyShape }).(KeyKeyShapeOutput)
}

// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
func (o KeyOutput) ManagementEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v *Key) pulumi.StringOutput { return v.ManagementEndpoint }).(pulumi.StringOutput)
}

// The key's protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault's RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key's protection mode is set to `HSM`. You can't change a key's protection mode after the key is created or imported.
func (o KeyOutput) ProtectionMode() pulumi.StringOutput {
	return o.ApplyT(func(v *Key) pulumi.StringOutput { return v.ProtectionMode }).(pulumi.StringOutput)
}

// Key replica details
func (o KeyOutput) ReplicaDetails() KeyReplicaDetailArrayOutput {
	return o.ApplyT(func(v *Key) KeyReplicaDetailArrayOutput { return v.ReplicaDetails }).(KeyReplicaDetailArrayOutput)
}

// (Updatable) Details where key was backed up.
func (o KeyOutput) RestoreFromFile() KeyRestoreFromFilePtrOutput {
	return o.ApplyT(func(v *Key) KeyRestoreFromFilePtrOutput { return v.RestoreFromFile }).(KeyRestoreFromFilePtrOutput)
}

// (Updatable) Details where key was backed up
func (o KeyOutput) RestoreFromObjectStore() KeyRestoreFromObjectStorePtrOutput {
	return o.ApplyT(func(v *Key) KeyRestoreFromObjectStorePtrOutput { return v.RestoreFromObjectStore }).(KeyRestoreFromObjectStorePtrOutput)
}

// (Updatable) An optional property when flipped triggers restore from restore option provided in config file.
func (o KeyOutput) RestoreTrigger() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v *Key) pulumi.BoolPtrOutput { return v.RestoreTrigger }).(pulumi.BoolPtrOutput)
}

// The OCID of the key from which this key was restored.
func (o KeyOutput) RestoredFromKeyId() pulumi.StringOutput {
	return o.ApplyT(func(v *Key) pulumi.StringOutput { return v.RestoredFromKeyId }).(pulumi.StringOutput)
}

// The key's current lifecycle state.  Example: `ENABLED`
func (o KeyOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Key) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the key was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-04-03T21:10:29.600Z`
func (o KeyOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Key) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// (Updatable) An optional property for the deletion time of the key, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
func (o KeyOutput) TimeOfDeletion() pulumi.StringOutput {
	return o.ApplyT(func(v *Key) pulumi.StringOutput { return v.TimeOfDeletion }).(pulumi.StringOutput)
}

// The OCID of the vault that contains this key.
func (o KeyOutput) VaultId() pulumi.StringOutput {
	return o.ApplyT(func(v *Key) pulumi.StringOutput { return v.VaultId }).(pulumi.StringOutput)
}

type KeyArrayOutput struct{ *pulumi.OutputState }

func (KeyArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Key)(nil)).Elem()
}

func (o KeyArrayOutput) ToKeyArrayOutput() KeyArrayOutput {
	return o
}

func (o KeyArrayOutput) ToKeyArrayOutputWithContext(ctx context.Context) KeyArrayOutput {
	return o
}

func (o KeyArrayOutput) Index(i pulumi.IntInput) KeyOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Key {
		return vs[0].([]*Key)[vs[1].(int)]
	}).(KeyOutput)
}

type KeyMapOutput struct{ *pulumi.OutputState }

func (KeyMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Key)(nil)).Elem()
}

func (o KeyMapOutput) ToKeyMapOutput() KeyMapOutput {
	return o
}

func (o KeyMapOutput) ToKeyMapOutputWithContext(ctx context.Context) KeyMapOutput {
	return o
}

func (o KeyMapOutput) MapIndex(k pulumi.StringInput) KeyOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Key {
		return vs[0].(map[string]*Key)[vs[1].(string)]
	}).(KeyOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*KeyInput)(nil)).Elem(), &Key{})
	pulumi.RegisterInputType(reflect.TypeOf((*KeyArrayInput)(nil)).Elem(), KeyArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*KeyMapInput)(nil)).Elem(), KeyMap{})
	pulumi.RegisterOutputType(KeyOutput{})
	pulumi.RegisterOutputType(KeyArrayOutput{})
	pulumi.RegisterOutputType(KeyMapOutput{})
}