// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package bigdataservice

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Bds Instance Metastore Config resource in Oracle Cloud Infrastructure Big Data Service service.
//
// Create and activate external metastore configuration.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/bigdataservice"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := bigdataservice.NewBdsInstanceMetastoreConfig(ctx, "test_bds_instance_metastore_config", &bigdataservice.BdsInstanceMetastoreConfigArgs{
//				BdsApiKeyId:          pulumi.Any(testApiKey.Id),
//				BdsApiKeyPassphrase:  pulumi.Any(bdsInstanceMetastoreConfigBdsApiKeyPassphrase),
//				BdsInstanceId:        pulumi.Any(testBdsInstance.Id),
//				ClusterAdminPassword: pulumi.Any(bdsInstanceMetastoreConfigClusterAdminPassword),
//				MetastoreId:          pulumi.Any(testMetastore.Id),
//				DisplayName:          pulumi.Any(bdsInstanceMetastoreConfigDisplayName),
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
// BdsInstanceMetastoreConfigs can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:BigDataService/bdsInstanceMetastoreConfig:BdsInstanceMetastoreConfig test_bds_instance_metastore_config "bdsInstances/{bdsInstanceId}/metastoreConfigs/{metastoreConfigId}"
// ```
type BdsInstanceMetastoreConfig struct {
	pulumi.CustomResourceState

	// (Updatable) An optional integer, when flipped triggers activation of metastore config.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ActivateTrigger pulumi.IntPtrOutput `pulumi:"activateTrigger"`
	// (Updatable) The ID of BDS Api Key used for Data Catalog metastore integration.
	BdsApiKeyId pulumi.StringOutput `pulumi:"bdsApiKeyId"`
	// (Updatable) Base-64 encoded passphrase of the BDS Api Key.
	BdsApiKeyPassphrase pulumi.StringOutput `pulumi:"bdsApiKeyPassphrase"`
	// The OCID of the cluster.
	BdsInstanceId pulumi.StringOutput `pulumi:"bdsInstanceId"`
	// (Updatable) Base-64 encoded password for the cluster admin user.
	ClusterAdminPassword pulumi.StringOutput `pulumi:"clusterAdminPassword"`
	// (Updatable) The display name of the metastore configuration
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The OCID of the Data Catalog metastore.
	MetastoreId pulumi.StringOutput `pulumi:"metastoreId"`
	// The type of the metastore in the metastore configuration.
	MetastoreType pulumi.StringOutput `pulumi:"metastoreType"`
	// the lifecycle state of the metastore configuration.
	State pulumi.StringOutput `pulumi:"state"`
	// The time when the configuration was created, shown as an RFC 3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time when the configuration was updated, shown as an RFC 3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewBdsInstanceMetastoreConfig registers a new resource with the given unique name, arguments, and options.
func NewBdsInstanceMetastoreConfig(ctx *pulumi.Context,
	name string, args *BdsInstanceMetastoreConfigArgs, opts ...pulumi.ResourceOption) (*BdsInstanceMetastoreConfig, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.BdsApiKeyId == nil {
		return nil, errors.New("invalid value for required argument 'BdsApiKeyId'")
	}
	if args.BdsApiKeyPassphrase == nil {
		return nil, errors.New("invalid value for required argument 'BdsApiKeyPassphrase'")
	}
	if args.BdsInstanceId == nil {
		return nil, errors.New("invalid value for required argument 'BdsInstanceId'")
	}
	if args.ClusterAdminPassword == nil {
		return nil, errors.New("invalid value for required argument 'ClusterAdminPassword'")
	}
	if args.MetastoreId == nil {
		return nil, errors.New("invalid value for required argument 'MetastoreId'")
	}
	if args.BdsApiKeyPassphrase != nil {
		args.BdsApiKeyPassphrase = pulumi.ToSecret(args.BdsApiKeyPassphrase).(pulumi.StringInput)
	}
	if args.ClusterAdminPassword != nil {
		args.ClusterAdminPassword = pulumi.ToSecret(args.ClusterAdminPassword).(pulumi.StringInput)
	}
	secrets := pulumi.AdditionalSecretOutputs([]string{
		"bdsApiKeyPassphrase",
		"clusterAdminPassword",
	})
	opts = append(opts, secrets)
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource BdsInstanceMetastoreConfig
	err := ctx.RegisterResource("oci:BigDataService/bdsInstanceMetastoreConfig:BdsInstanceMetastoreConfig", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetBdsInstanceMetastoreConfig gets an existing BdsInstanceMetastoreConfig resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetBdsInstanceMetastoreConfig(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *BdsInstanceMetastoreConfigState, opts ...pulumi.ResourceOption) (*BdsInstanceMetastoreConfig, error) {
	var resource BdsInstanceMetastoreConfig
	err := ctx.ReadResource("oci:BigDataService/bdsInstanceMetastoreConfig:BdsInstanceMetastoreConfig", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering BdsInstanceMetastoreConfig resources.
type bdsInstanceMetastoreConfigState struct {
	// (Updatable) An optional integer, when flipped triggers activation of metastore config.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ActivateTrigger *int `pulumi:"activateTrigger"`
	// (Updatable) The ID of BDS Api Key used for Data Catalog metastore integration.
	BdsApiKeyId *string `pulumi:"bdsApiKeyId"`
	// (Updatable) Base-64 encoded passphrase of the BDS Api Key.
	BdsApiKeyPassphrase *string `pulumi:"bdsApiKeyPassphrase"`
	// The OCID of the cluster.
	BdsInstanceId *string `pulumi:"bdsInstanceId"`
	// (Updatable) Base-64 encoded password for the cluster admin user.
	ClusterAdminPassword *string `pulumi:"clusterAdminPassword"`
	// (Updatable) The display name of the metastore configuration
	DisplayName *string `pulumi:"displayName"`
	// The OCID of the Data Catalog metastore.
	MetastoreId *string `pulumi:"metastoreId"`
	// The type of the metastore in the metastore configuration.
	MetastoreType *string `pulumi:"metastoreType"`
	// the lifecycle state of the metastore configuration.
	State *string `pulumi:"state"`
	// The time when the configuration was created, shown as an RFC 3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time when the configuration was updated, shown as an RFC 3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type BdsInstanceMetastoreConfigState struct {
	// (Updatable) An optional integer, when flipped triggers activation of metastore config.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ActivateTrigger pulumi.IntPtrInput
	// (Updatable) The ID of BDS Api Key used for Data Catalog metastore integration.
	BdsApiKeyId pulumi.StringPtrInput
	// (Updatable) Base-64 encoded passphrase of the BDS Api Key.
	BdsApiKeyPassphrase pulumi.StringPtrInput
	// The OCID of the cluster.
	BdsInstanceId pulumi.StringPtrInput
	// (Updatable) Base-64 encoded password for the cluster admin user.
	ClusterAdminPassword pulumi.StringPtrInput
	// (Updatable) The display name of the metastore configuration
	DisplayName pulumi.StringPtrInput
	// The OCID of the Data Catalog metastore.
	MetastoreId pulumi.StringPtrInput
	// The type of the metastore in the metastore configuration.
	MetastoreType pulumi.StringPtrInput
	// the lifecycle state of the metastore configuration.
	State pulumi.StringPtrInput
	// The time when the configuration was created, shown as an RFC 3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time when the configuration was updated, shown as an RFC 3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
}

func (BdsInstanceMetastoreConfigState) ElementType() reflect.Type {
	return reflect.TypeOf((*bdsInstanceMetastoreConfigState)(nil)).Elem()
}

type bdsInstanceMetastoreConfigArgs struct {
	// (Updatable) An optional integer, when flipped triggers activation of metastore config.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ActivateTrigger *int `pulumi:"activateTrigger"`
	// (Updatable) The ID of BDS Api Key used for Data Catalog metastore integration.
	BdsApiKeyId string `pulumi:"bdsApiKeyId"`
	// (Updatable) Base-64 encoded passphrase of the BDS Api Key.
	BdsApiKeyPassphrase string `pulumi:"bdsApiKeyPassphrase"`
	// The OCID of the cluster.
	BdsInstanceId string `pulumi:"bdsInstanceId"`
	// (Updatable) Base-64 encoded password for the cluster admin user.
	ClusterAdminPassword string `pulumi:"clusterAdminPassword"`
	// (Updatable) The display name of the metastore configuration
	DisplayName *string `pulumi:"displayName"`
	// The OCID of the Data Catalog metastore.
	MetastoreId string `pulumi:"metastoreId"`
}

// The set of arguments for constructing a BdsInstanceMetastoreConfig resource.
type BdsInstanceMetastoreConfigArgs struct {
	// (Updatable) An optional integer, when flipped triggers activation of metastore config.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ActivateTrigger pulumi.IntPtrInput
	// (Updatable) The ID of BDS Api Key used for Data Catalog metastore integration.
	BdsApiKeyId pulumi.StringInput
	// (Updatable) Base-64 encoded passphrase of the BDS Api Key.
	BdsApiKeyPassphrase pulumi.StringInput
	// The OCID of the cluster.
	BdsInstanceId pulumi.StringInput
	// (Updatable) Base-64 encoded password for the cluster admin user.
	ClusterAdminPassword pulumi.StringInput
	// (Updatable) The display name of the metastore configuration
	DisplayName pulumi.StringPtrInput
	// The OCID of the Data Catalog metastore.
	MetastoreId pulumi.StringInput
}

func (BdsInstanceMetastoreConfigArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*bdsInstanceMetastoreConfigArgs)(nil)).Elem()
}

type BdsInstanceMetastoreConfigInput interface {
	pulumi.Input

	ToBdsInstanceMetastoreConfigOutput() BdsInstanceMetastoreConfigOutput
	ToBdsInstanceMetastoreConfigOutputWithContext(ctx context.Context) BdsInstanceMetastoreConfigOutput
}

func (*BdsInstanceMetastoreConfig) ElementType() reflect.Type {
	return reflect.TypeOf((**BdsInstanceMetastoreConfig)(nil)).Elem()
}

func (i *BdsInstanceMetastoreConfig) ToBdsInstanceMetastoreConfigOutput() BdsInstanceMetastoreConfigOutput {
	return i.ToBdsInstanceMetastoreConfigOutputWithContext(context.Background())
}

func (i *BdsInstanceMetastoreConfig) ToBdsInstanceMetastoreConfigOutputWithContext(ctx context.Context) BdsInstanceMetastoreConfigOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BdsInstanceMetastoreConfigOutput)
}

// BdsInstanceMetastoreConfigArrayInput is an input type that accepts BdsInstanceMetastoreConfigArray and BdsInstanceMetastoreConfigArrayOutput values.
// You can construct a concrete instance of `BdsInstanceMetastoreConfigArrayInput` via:
//
//	BdsInstanceMetastoreConfigArray{ BdsInstanceMetastoreConfigArgs{...} }
type BdsInstanceMetastoreConfigArrayInput interface {
	pulumi.Input

	ToBdsInstanceMetastoreConfigArrayOutput() BdsInstanceMetastoreConfigArrayOutput
	ToBdsInstanceMetastoreConfigArrayOutputWithContext(context.Context) BdsInstanceMetastoreConfigArrayOutput
}

type BdsInstanceMetastoreConfigArray []BdsInstanceMetastoreConfigInput

func (BdsInstanceMetastoreConfigArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*BdsInstanceMetastoreConfig)(nil)).Elem()
}

func (i BdsInstanceMetastoreConfigArray) ToBdsInstanceMetastoreConfigArrayOutput() BdsInstanceMetastoreConfigArrayOutput {
	return i.ToBdsInstanceMetastoreConfigArrayOutputWithContext(context.Background())
}

func (i BdsInstanceMetastoreConfigArray) ToBdsInstanceMetastoreConfigArrayOutputWithContext(ctx context.Context) BdsInstanceMetastoreConfigArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BdsInstanceMetastoreConfigArrayOutput)
}

// BdsInstanceMetastoreConfigMapInput is an input type that accepts BdsInstanceMetastoreConfigMap and BdsInstanceMetastoreConfigMapOutput values.
// You can construct a concrete instance of `BdsInstanceMetastoreConfigMapInput` via:
//
//	BdsInstanceMetastoreConfigMap{ "key": BdsInstanceMetastoreConfigArgs{...} }
type BdsInstanceMetastoreConfigMapInput interface {
	pulumi.Input

	ToBdsInstanceMetastoreConfigMapOutput() BdsInstanceMetastoreConfigMapOutput
	ToBdsInstanceMetastoreConfigMapOutputWithContext(context.Context) BdsInstanceMetastoreConfigMapOutput
}

type BdsInstanceMetastoreConfigMap map[string]BdsInstanceMetastoreConfigInput

func (BdsInstanceMetastoreConfigMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*BdsInstanceMetastoreConfig)(nil)).Elem()
}

func (i BdsInstanceMetastoreConfigMap) ToBdsInstanceMetastoreConfigMapOutput() BdsInstanceMetastoreConfigMapOutput {
	return i.ToBdsInstanceMetastoreConfigMapOutputWithContext(context.Background())
}

func (i BdsInstanceMetastoreConfigMap) ToBdsInstanceMetastoreConfigMapOutputWithContext(ctx context.Context) BdsInstanceMetastoreConfigMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BdsInstanceMetastoreConfigMapOutput)
}

type BdsInstanceMetastoreConfigOutput struct{ *pulumi.OutputState }

func (BdsInstanceMetastoreConfigOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**BdsInstanceMetastoreConfig)(nil)).Elem()
}

func (o BdsInstanceMetastoreConfigOutput) ToBdsInstanceMetastoreConfigOutput() BdsInstanceMetastoreConfigOutput {
	return o
}

func (o BdsInstanceMetastoreConfigOutput) ToBdsInstanceMetastoreConfigOutputWithContext(ctx context.Context) BdsInstanceMetastoreConfigOutput {
	return o
}

// (Updatable) An optional integer, when flipped triggers activation of metastore config.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o BdsInstanceMetastoreConfigOutput) ActivateTrigger() pulumi.IntPtrOutput {
	return o.ApplyT(func(v *BdsInstanceMetastoreConfig) pulumi.IntPtrOutput { return v.ActivateTrigger }).(pulumi.IntPtrOutput)
}

// (Updatable) The ID of BDS Api Key used for Data Catalog metastore integration.
func (o BdsInstanceMetastoreConfigOutput) BdsApiKeyId() pulumi.StringOutput {
	return o.ApplyT(func(v *BdsInstanceMetastoreConfig) pulumi.StringOutput { return v.BdsApiKeyId }).(pulumi.StringOutput)
}

// (Updatable) Base-64 encoded passphrase of the BDS Api Key.
func (o BdsInstanceMetastoreConfigOutput) BdsApiKeyPassphrase() pulumi.StringOutput {
	return o.ApplyT(func(v *BdsInstanceMetastoreConfig) pulumi.StringOutput { return v.BdsApiKeyPassphrase }).(pulumi.StringOutput)
}

// The OCID of the cluster.
func (o BdsInstanceMetastoreConfigOutput) BdsInstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v *BdsInstanceMetastoreConfig) pulumi.StringOutput { return v.BdsInstanceId }).(pulumi.StringOutput)
}

// (Updatable) Base-64 encoded password for the cluster admin user.
func (o BdsInstanceMetastoreConfigOutput) ClusterAdminPassword() pulumi.StringOutput {
	return o.ApplyT(func(v *BdsInstanceMetastoreConfig) pulumi.StringOutput { return v.ClusterAdminPassword }).(pulumi.StringOutput)
}

// (Updatable) The display name of the metastore configuration
func (o BdsInstanceMetastoreConfigOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *BdsInstanceMetastoreConfig) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// The OCID of the Data Catalog metastore.
func (o BdsInstanceMetastoreConfigOutput) MetastoreId() pulumi.StringOutput {
	return o.ApplyT(func(v *BdsInstanceMetastoreConfig) pulumi.StringOutput { return v.MetastoreId }).(pulumi.StringOutput)
}

// The type of the metastore in the metastore configuration.
func (o BdsInstanceMetastoreConfigOutput) MetastoreType() pulumi.StringOutput {
	return o.ApplyT(func(v *BdsInstanceMetastoreConfig) pulumi.StringOutput { return v.MetastoreType }).(pulumi.StringOutput)
}

// the lifecycle state of the metastore configuration.
func (o BdsInstanceMetastoreConfigOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *BdsInstanceMetastoreConfig) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The time when the configuration was created, shown as an RFC 3339 formatted datetime string.
func (o BdsInstanceMetastoreConfigOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *BdsInstanceMetastoreConfig) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when the configuration was updated, shown as an RFC 3339 formatted datetime string.
func (o BdsInstanceMetastoreConfigOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *BdsInstanceMetastoreConfig) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type BdsInstanceMetastoreConfigArrayOutput struct{ *pulumi.OutputState }

func (BdsInstanceMetastoreConfigArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*BdsInstanceMetastoreConfig)(nil)).Elem()
}

func (o BdsInstanceMetastoreConfigArrayOutput) ToBdsInstanceMetastoreConfigArrayOutput() BdsInstanceMetastoreConfigArrayOutput {
	return o
}

func (o BdsInstanceMetastoreConfigArrayOutput) ToBdsInstanceMetastoreConfigArrayOutputWithContext(ctx context.Context) BdsInstanceMetastoreConfigArrayOutput {
	return o
}

func (o BdsInstanceMetastoreConfigArrayOutput) Index(i pulumi.IntInput) BdsInstanceMetastoreConfigOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *BdsInstanceMetastoreConfig {
		return vs[0].([]*BdsInstanceMetastoreConfig)[vs[1].(int)]
	}).(BdsInstanceMetastoreConfigOutput)
}

type BdsInstanceMetastoreConfigMapOutput struct{ *pulumi.OutputState }

func (BdsInstanceMetastoreConfigMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*BdsInstanceMetastoreConfig)(nil)).Elem()
}

func (o BdsInstanceMetastoreConfigMapOutput) ToBdsInstanceMetastoreConfigMapOutput() BdsInstanceMetastoreConfigMapOutput {
	return o
}

func (o BdsInstanceMetastoreConfigMapOutput) ToBdsInstanceMetastoreConfigMapOutputWithContext(ctx context.Context) BdsInstanceMetastoreConfigMapOutput {
	return o
}

func (o BdsInstanceMetastoreConfigMapOutput) MapIndex(k pulumi.StringInput) BdsInstanceMetastoreConfigOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *BdsInstanceMetastoreConfig {
		return vs[0].(map[string]*BdsInstanceMetastoreConfig)[vs[1].(string)]
	}).(BdsInstanceMetastoreConfigOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*BdsInstanceMetastoreConfigInput)(nil)).Elem(), &BdsInstanceMetastoreConfig{})
	pulumi.RegisterInputType(reflect.TypeOf((*BdsInstanceMetastoreConfigArrayInput)(nil)).Elem(), BdsInstanceMetastoreConfigArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*BdsInstanceMetastoreConfigMapInput)(nil)).Elem(), BdsInstanceMetastoreConfigMap{})
	pulumi.RegisterOutputType(BdsInstanceMetastoreConfigOutput{})
	pulumi.RegisterOutputType(BdsInstanceMetastoreConfigArrayOutput{})
	pulumi.RegisterOutputType(BdsInstanceMetastoreConfigMapOutput{})
}
