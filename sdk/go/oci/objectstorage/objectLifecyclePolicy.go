// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package objectstorage

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Object Lifecycle Policy resource in Oracle Cloud Infrastructure Object Storage service.
//
// Creates or replaces the object lifecycle policy for the bucket.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/ObjectStorage"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := ObjectStorage.NewObjectLifecyclePolicy(ctx, "testObjectLifecyclePolicy", &ObjectStorage.ObjectLifecyclePolicyArgs{
// 			Bucket:    pulumi.Any(_var.Object_lifecycle_policy_bucket),
// 			Namespace: pulumi.Any(_var.Object_lifecycle_policy_namespace),
// 			Rules: objectstorage.ObjectLifecyclePolicyRuleArray{
// 				&objectstorage.ObjectLifecyclePolicyRuleArgs{
// 					Action:     pulumi.Any(_var.Object_lifecycle_policy_rules_action),
// 					IsEnabled:  pulumi.Any(_var.Object_lifecycle_policy_rules_is_enabled),
// 					Name:       pulumi.Any(_var.Object_lifecycle_policy_rules_name),
// 					TimeAmount: pulumi.Any(_var.Object_lifecycle_policy_rules_time_amount),
// 					TimeUnit:   pulumi.Any(_var.Object_lifecycle_policy_rules_time_unit),
// 					ObjectNameFilter: &objectstorage.ObjectLifecyclePolicyRuleObjectNameFilterArgs{
// 						ExclusionPatterns: pulumi.Any(_var.Object_lifecycle_policy_rules_object_name_filter_exclusion_patterns),
// 						InclusionPatterns: pulumi.Any(_var.Object_lifecycle_policy_rules_object_name_filter_inclusion_patterns),
// 						InclusionPrefixes: pulumi.Any(_var.Object_lifecycle_policy_rules_object_name_filter_inclusion_prefixes),
// 					},
// 					Target: pulumi.Any(_var.Object_lifecycle_policy_rules_target),
// 				},
// 			},
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
//
// ## Import
//
// ObjectLifecyclePolicies can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:ObjectStorage/objectLifecyclePolicy:ObjectLifecyclePolicy test_object_lifecycle_policy "n/{namespaceName}/b/{bucketName}/l"
// ```
type ObjectLifecyclePolicy struct {
	pulumi.CustomResourceState

	// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
	Bucket pulumi.StringOutput `pulumi:"bucket"`
	// The Object Storage namespace used for the request.
	Namespace pulumi.StringOutput `pulumi:"namespace"`
	// (Updatable) The bucket's set of lifecycle policy rules.
	Rules ObjectLifecyclePolicyRuleArrayOutput `pulumi:"rules"`
	// The date and time the object lifecycle policy was created, as described in [RFC 3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewObjectLifecyclePolicy registers a new resource with the given unique name, arguments, and options.
func NewObjectLifecyclePolicy(ctx *pulumi.Context,
	name string, args *ObjectLifecyclePolicyArgs, opts ...pulumi.ResourceOption) (*ObjectLifecyclePolicy, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Bucket == nil {
		return nil, errors.New("invalid value for required argument 'Bucket'")
	}
	if args.Namespace == nil {
		return nil, errors.New("invalid value for required argument 'Namespace'")
	}
	var resource ObjectLifecyclePolicy
	err := ctx.RegisterResource("oci:ObjectStorage/objectLifecyclePolicy:ObjectLifecyclePolicy", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetObjectLifecyclePolicy gets an existing ObjectLifecyclePolicy resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetObjectLifecyclePolicy(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ObjectLifecyclePolicyState, opts ...pulumi.ResourceOption) (*ObjectLifecyclePolicy, error) {
	var resource ObjectLifecyclePolicy
	err := ctx.ReadResource("oci:ObjectStorage/objectLifecyclePolicy:ObjectLifecyclePolicy", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ObjectLifecyclePolicy resources.
type objectLifecyclePolicyState struct {
	// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
	Bucket *string `pulumi:"bucket"`
	// The Object Storage namespace used for the request.
	Namespace *string `pulumi:"namespace"`
	// (Updatable) The bucket's set of lifecycle policy rules.
	Rules []ObjectLifecyclePolicyRule `pulumi:"rules"`
	// The date and time the object lifecycle policy was created, as described in [RFC 3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
}

type ObjectLifecyclePolicyState struct {
	// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
	Bucket pulumi.StringPtrInput
	// The Object Storage namespace used for the request.
	Namespace pulumi.StringPtrInput
	// (Updatable) The bucket's set of lifecycle policy rules.
	Rules ObjectLifecyclePolicyRuleArrayInput
	// The date and time the object lifecycle policy was created, as described in [RFC 3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
}

func (ObjectLifecyclePolicyState) ElementType() reflect.Type {
	return reflect.TypeOf((*objectLifecyclePolicyState)(nil)).Elem()
}

type objectLifecyclePolicyArgs struct {
	// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
	Bucket string `pulumi:"bucket"`
	// The Object Storage namespace used for the request.
	Namespace string `pulumi:"namespace"`
	// (Updatable) The bucket's set of lifecycle policy rules.
	Rules []ObjectLifecyclePolicyRule `pulumi:"rules"`
}

// The set of arguments for constructing a ObjectLifecyclePolicy resource.
type ObjectLifecyclePolicyArgs struct {
	// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
	Bucket pulumi.StringInput
	// The Object Storage namespace used for the request.
	Namespace pulumi.StringInput
	// (Updatable) The bucket's set of lifecycle policy rules.
	Rules ObjectLifecyclePolicyRuleArrayInput
}

func (ObjectLifecyclePolicyArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*objectLifecyclePolicyArgs)(nil)).Elem()
}

type ObjectLifecyclePolicyInput interface {
	pulumi.Input

	ToObjectLifecyclePolicyOutput() ObjectLifecyclePolicyOutput
	ToObjectLifecyclePolicyOutputWithContext(ctx context.Context) ObjectLifecyclePolicyOutput
}

func (*ObjectLifecyclePolicy) ElementType() reflect.Type {
	return reflect.TypeOf((**ObjectLifecyclePolicy)(nil)).Elem()
}

func (i *ObjectLifecyclePolicy) ToObjectLifecyclePolicyOutput() ObjectLifecyclePolicyOutput {
	return i.ToObjectLifecyclePolicyOutputWithContext(context.Background())
}

func (i *ObjectLifecyclePolicy) ToObjectLifecyclePolicyOutputWithContext(ctx context.Context) ObjectLifecyclePolicyOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ObjectLifecyclePolicyOutput)
}

// ObjectLifecyclePolicyArrayInput is an input type that accepts ObjectLifecyclePolicyArray and ObjectLifecyclePolicyArrayOutput values.
// You can construct a concrete instance of `ObjectLifecyclePolicyArrayInput` via:
//
//          ObjectLifecyclePolicyArray{ ObjectLifecyclePolicyArgs{...} }
type ObjectLifecyclePolicyArrayInput interface {
	pulumi.Input

	ToObjectLifecyclePolicyArrayOutput() ObjectLifecyclePolicyArrayOutput
	ToObjectLifecyclePolicyArrayOutputWithContext(context.Context) ObjectLifecyclePolicyArrayOutput
}

type ObjectLifecyclePolicyArray []ObjectLifecyclePolicyInput

func (ObjectLifecyclePolicyArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ObjectLifecyclePolicy)(nil)).Elem()
}

func (i ObjectLifecyclePolicyArray) ToObjectLifecyclePolicyArrayOutput() ObjectLifecyclePolicyArrayOutput {
	return i.ToObjectLifecyclePolicyArrayOutputWithContext(context.Background())
}

func (i ObjectLifecyclePolicyArray) ToObjectLifecyclePolicyArrayOutputWithContext(ctx context.Context) ObjectLifecyclePolicyArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ObjectLifecyclePolicyArrayOutput)
}

// ObjectLifecyclePolicyMapInput is an input type that accepts ObjectLifecyclePolicyMap and ObjectLifecyclePolicyMapOutput values.
// You can construct a concrete instance of `ObjectLifecyclePolicyMapInput` via:
//
//          ObjectLifecyclePolicyMap{ "key": ObjectLifecyclePolicyArgs{...} }
type ObjectLifecyclePolicyMapInput interface {
	pulumi.Input

	ToObjectLifecyclePolicyMapOutput() ObjectLifecyclePolicyMapOutput
	ToObjectLifecyclePolicyMapOutputWithContext(context.Context) ObjectLifecyclePolicyMapOutput
}

type ObjectLifecyclePolicyMap map[string]ObjectLifecyclePolicyInput

func (ObjectLifecyclePolicyMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ObjectLifecyclePolicy)(nil)).Elem()
}

func (i ObjectLifecyclePolicyMap) ToObjectLifecyclePolicyMapOutput() ObjectLifecyclePolicyMapOutput {
	return i.ToObjectLifecyclePolicyMapOutputWithContext(context.Background())
}

func (i ObjectLifecyclePolicyMap) ToObjectLifecyclePolicyMapOutputWithContext(ctx context.Context) ObjectLifecyclePolicyMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ObjectLifecyclePolicyMapOutput)
}

type ObjectLifecyclePolicyOutput struct{ *pulumi.OutputState }

func (ObjectLifecyclePolicyOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ObjectLifecyclePolicy)(nil)).Elem()
}

func (o ObjectLifecyclePolicyOutput) ToObjectLifecyclePolicyOutput() ObjectLifecyclePolicyOutput {
	return o
}

func (o ObjectLifecyclePolicyOutput) ToObjectLifecyclePolicyOutputWithContext(ctx context.Context) ObjectLifecyclePolicyOutput {
	return o
}

type ObjectLifecyclePolicyArrayOutput struct{ *pulumi.OutputState }

func (ObjectLifecyclePolicyArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ObjectLifecyclePolicy)(nil)).Elem()
}

func (o ObjectLifecyclePolicyArrayOutput) ToObjectLifecyclePolicyArrayOutput() ObjectLifecyclePolicyArrayOutput {
	return o
}

func (o ObjectLifecyclePolicyArrayOutput) ToObjectLifecyclePolicyArrayOutputWithContext(ctx context.Context) ObjectLifecyclePolicyArrayOutput {
	return o
}

func (o ObjectLifecyclePolicyArrayOutput) Index(i pulumi.IntInput) ObjectLifecyclePolicyOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ObjectLifecyclePolicy {
		return vs[0].([]*ObjectLifecyclePolicy)[vs[1].(int)]
	}).(ObjectLifecyclePolicyOutput)
}

type ObjectLifecyclePolicyMapOutput struct{ *pulumi.OutputState }

func (ObjectLifecyclePolicyMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ObjectLifecyclePolicy)(nil)).Elem()
}

func (o ObjectLifecyclePolicyMapOutput) ToObjectLifecyclePolicyMapOutput() ObjectLifecyclePolicyMapOutput {
	return o
}

func (o ObjectLifecyclePolicyMapOutput) ToObjectLifecyclePolicyMapOutputWithContext(ctx context.Context) ObjectLifecyclePolicyMapOutput {
	return o
}

func (o ObjectLifecyclePolicyMapOutput) MapIndex(k pulumi.StringInput) ObjectLifecyclePolicyOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ObjectLifecyclePolicy {
		return vs[0].(map[string]*ObjectLifecyclePolicy)[vs[1].(string)]
	}).(ObjectLifecyclePolicyOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ObjectLifecyclePolicyInput)(nil)).Elem(), &ObjectLifecyclePolicy{})
	pulumi.RegisterInputType(reflect.TypeOf((*ObjectLifecyclePolicyArrayInput)(nil)).Elem(), ObjectLifecyclePolicyArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ObjectLifecyclePolicyMapInput)(nil)).Elem(), ObjectLifecyclePolicyMap{})
	pulumi.RegisterOutputType(ObjectLifecyclePolicyOutput{})
	pulumi.RegisterOutputType(ObjectLifecyclePolicyArrayOutput{})
	pulumi.RegisterOutputType(ObjectLifecyclePolicyMapOutput{})
}
