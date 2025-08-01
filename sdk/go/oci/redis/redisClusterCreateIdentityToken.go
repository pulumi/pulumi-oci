// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package redis

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Redis Cluster Create Identity Token resource in Oracle Cloud Infrastructure Redis service.
//
// # Generates an identity token to sign in with the specified redis user for the redis cluster
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/redis"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := redis.NewRedisClusterCreateIdentityToken(ctx, "test_redis_cluster_create_identity_token", &redis.RedisClusterCreateIdentityTokenArgs{
//				PublicKey:      pulumi.Any(redisClusterCreateIdentityTokenPublicKey),
//				RedisClusterId: pulumi.Any(testRedisCluster.Id),
//				RedisUser:      pulumi.Any(redisClusterCreateIdentityTokenRedisUser),
//				DefinedTags:    pulumi.Any(redisClusterCreateIdentityTokenDefinedTags),
//				FreeformTags:   pulumi.Any(redisClusterCreateIdentityTokenFreeformTags),
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
// Import is not supported for this resource.
type RedisClusterCreateIdentityToken struct {
	pulumi.CustomResourceState

	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// Generated Identity token
	IdentityToken pulumi.StringOutput `pulumi:"identityToken"`
	// User public key pair
	PublicKey pulumi.StringOutput `pulumi:"publicKey"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
	RedisClusterId pulumi.StringOutput `pulumi:"redisClusterId"`
	// Redis User generating identity token.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	RedisUser pulumi.StringOutput `pulumi:"redisUser"`
}

// NewRedisClusterCreateIdentityToken registers a new resource with the given unique name, arguments, and options.
func NewRedisClusterCreateIdentityToken(ctx *pulumi.Context,
	name string, args *RedisClusterCreateIdentityTokenArgs, opts ...pulumi.ResourceOption) (*RedisClusterCreateIdentityToken, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.PublicKey == nil {
		return nil, errors.New("invalid value for required argument 'PublicKey'")
	}
	if args.RedisClusterId == nil {
		return nil, errors.New("invalid value for required argument 'RedisClusterId'")
	}
	if args.RedisUser == nil {
		return nil, errors.New("invalid value for required argument 'RedisUser'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource RedisClusterCreateIdentityToken
	err := ctx.RegisterResource("oci:Redis/redisClusterCreateIdentityToken:RedisClusterCreateIdentityToken", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetRedisClusterCreateIdentityToken gets an existing RedisClusterCreateIdentityToken resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetRedisClusterCreateIdentityToken(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *RedisClusterCreateIdentityTokenState, opts ...pulumi.ResourceOption) (*RedisClusterCreateIdentityToken, error) {
	var resource RedisClusterCreateIdentityToken
	err := ctx.ReadResource("oci:Redis/redisClusterCreateIdentityToken:RedisClusterCreateIdentityToken", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering RedisClusterCreateIdentityToken resources.
type redisClusterCreateIdentityTokenState struct {
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// Generated Identity token
	IdentityToken *string `pulumi:"identityToken"`
	// User public key pair
	PublicKey *string `pulumi:"publicKey"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
	RedisClusterId *string `pulumi:"redisClusterId"`
	// Redis User generating identity token.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	RedisUser *string `pulumi:"redisUser"`
}

type RedisClusterCreateIdentityTokenState struct {
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// Generated Identity token
	IdentityToken pulumi.StringPtrInput
	// User public key pair
	PublicKey pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
	RedisClusterId pulumi.StringPtrInput
	// Redis User generating identity token.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	RedisUser pulumi.StringPtrInput
}

func (RedisClusterCreateIdentityTokenState) ElementType() reflect.Type {
	return reflect.TypeOf((*redisClusterCreateIdentityTokenState)(nil)).Elem()
}

type redisClusterCreateIdentityTokenArgs struct {
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// User public key pair
	PublicKey string `pulumi:"publicKey"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
	RedisClusterId string `pulumi:"redisClusterId"`
	// Redis User generating identity token.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	RedisUser string `pulumi:"redisUser"`
}

// The set of arguments for constructing a RedisClusterCreateIdentityToken resource.
type RedisClusterCreateIdentityTokenArgs struct {
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// User public key pair
	PublicKey pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
	RedisClusterId pulumi.StringInput
	// Redis User generating identity token.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	RedisUser pulumi.StringInput
}

func (RedisClusterCreateIdentityTokenArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*redisClusterCreateIdentityTokenArgs)(nil)).Elem()
}

type RedisClusterCreateIdentityTokenInput interface {
	pulumi.Input

	ToRedisClusterCreateIdentityTokenOutput() RedisClusterCreateIdentityTokenOutput
	ToRedisClusterCreateIdentityTokenOutputWithContext(ctx context.Context) RedisClusterCreateIdentityTokenOutput
}

func (*RedisClusterCreateIdentityToken) ElementType() reflect.Type {
	return reflect.TypeOf((**RedisClusterCreateIdentityToken)(nil)).Elem()
}

func (i *RedisClusterCreateIdentityToken) ToRedisClusterCreateIdentityTokenOutput() RedisClusterCreateIdentityTokenOutput {
	return i.ToRedisClusterCreateIdentityTokenOutputWithContext(context.Background())
}

func (i *RedisClusterCreateIdentityToken) ToRedisClusterCreateIdentityTokenOutputWithContext(ctx context.Context) RedisClusterCreateIdentityTokenOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RedisClusterCreateIdentityTokenOutput)
}

// RedisClusterCreateIdentityTokenArrayInput is an input type that accepts RedisClusterCreateIdentityTokenArray and RedisClusterCreateIdentityTokenArrayOutput values.
// You can construct a concrete instance of `RedisClusterCreateIdentityTokenArrayInput` via:
//
//	RedisClusterCreateIdentityTokenArray{ RedisClusterCreateIdentityTokenArgs{...} }
type RedisClusterCreateIdentityTokenArrayInput interface {
	pulumi.Input

	ToRedisClusterCreateIdentityTokenArrayOutput() RedisClusterCreateIdentityTokenArrayOutput
	ToRedisClusterCreateIdentityTokenArrayOutputWithContext(context.Context) RedisClusterCreateIdentityTokenArrayOutput
}

type RedisClusterCreateIdentityTokenArray []RedisClusterCreateIdentityTokenInput

func (RedisClusterCreateIdentityTokenArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*RedisClusterCreateIdentityToken)(nil)).Elem()
}

func (i RedisClusterCreateIdentityTokenArray) ToRedisClusterCreateIdentityTokenArrayOutput() RedisClusterCreateIdentityTokenArrayOutput {
	return i.ToRedisClusterCreateIdentityTokenArrayOutputWithContext(context.Background())
}

func (i RedisClusterCreateIdentityTokenArray) ToRedisClusterCreateIdentityTokenArrayOutputWithContext(ctx context.Context) RedisClusterCreateIdentityTokenArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RedisClusterCreateIdentityTokenArrayOutput)
}

// RedisClusterCreateIdentityTokenMapInput is an input type that accepts RedisClusterCreateIdentityTokenMap and RedisClusterCreateIdentityTokenMapOutput values.
// You can construct a concrete instance of `RedisClusterCreateIdentityTokenMapInput` via:
//
//	RedisClusterCreateIdentityTokenMap{ "key": RedisClusterCreateIdentityTokenArgs{...} }
type RedisClusterCreateIdentityTokenMapInput interface {
	pulumi.Input

	ToRedisClusterCreateIdentityTokenMapOutput() RedisClusterCreateIdentityTokenMapOutput
	ToRedisClusterCreateIdentityTokenMapOutputWithContext(context.Context) RedisClusterCreateIdentityTokenMapOutput
}

type RedisClusterCreateIdentityTokenMap map[string]RedisClusterCreateIdentityTokenInput

func (RedisClusterCreateIdentityTokenMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*RedisClusterCreateIdentityToken)(nil)).Elem()
}

func (i RedisClusterCreateIdentityTokenMap) ToRedisClusterCreateIdentityTokenMapOutput() RedisClusterCreateIdentityTokenMapOutput {
	return i.ToRedisClusterCreateIdentityTokenMapOutputWithContext(context.Background())
}

func (i RedisClusterCreateIdentityTokenMap) ToRedisClusterCreateIdentityTokenMapOutputWithContext(ctx context.Context) RedisClusterCreateIdentityTokenMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RedisClusterCreateIdentityTokenMapOutput)
}

type RedisClusterCreateIdentityTokenOutput struct{ *pulumi.OutputState }

func (RedisClusterCreateIdentityTokenOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**RedisClusterCreateIdentityToken)(nil)).Elem()
}

func (o RedisClusterCreateIdentityTokenOutput) ToRedisClusterCreateIdentityTokenOutput() RedisClusterCreateIdentityTokenOutput {
	return o
}

func (o RedisClusterCreateIdentityTokenOutput) ToRedisClusterCreateIdentityTokenOutputWithContext(ctx context.Context) RedisClusterCreateIdentityTokenOutput {
	return o
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o RedisClusterCreateIdentityTokenOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *RedisClusterCreateIdentityToken) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o RedisClusterCreateIdentityTokenOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *RedisClusterCreateIdentityToken) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// Generated Identity token
func (o RedisClusterCreateIdentityTokenOutput) IdentityToken() pulumi.StringOutput {
	return o.ApplyT(func(v *RedisClusterCreateIdentityToken) pulumi.StringOutput { return v.IdentityToken }).(pulumi.StringOutput)
}

// User public key pair
func (o RedisClusterCreateIdentityTokenOutput) PublicKey() pulumi.StringOutput {
	return o.ApplyT(func(v *RedisClusterCreateIdentityToken) pulumi.StringOutput { return v.PublicKey }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
func (o RedisClusterCreateIdentityTokenOutput) RedisClusterId() pulumi.StringOutput {
	return o.ApplyT(func(v *RedisClusterCreateIdentityToken) pulumi.StringOutput { return v.RedisClusterId }).(pulumi.StringOutput)
}

// Redis User generating identity token.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o RedisClusterCreateIdentityTokenOutput) RedisUser() pulumi.StringOutput {
	return o.ApplyT(func(v *RedisClusterCreateIdentityToken) pulumi.StringOutput { return v.RedisUser }).(pulumi.StringOutput)
}

type RedisClusterCreateIdentityTokenArrayOutput struct{ *pulumi.OutputState }

func (RedisClusterCreateIdentityTokenArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*RedisClusterCreateIdentityToken)(nil)).Elem()
}

func (o RedisClusterCreateIdentityTokenArrayOutput) ToRedisClusterCreateIdentityTokenArrayOutput() RedisClusterCreateIdentityTokenArrayOutput {
	return o
}

func (o RedisClusterCreateIdentityTokenArrayOutput) ToRedisClusterCreateIdentityTokenArrayOutputWithContext(ctx context.Context) RedisClusterCreateIdentityTokenArrayOutput {
	return o
}

func (o RedisClusterCreateIdentityTokenArrayOutput) Index(i pulumi.IntInput) RedisClusterCreateIdentityTokenOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *RedisClusterCreateIdentityToken {
		return vs[0].([]*RedisClusterCreateIdentityToken)[vs[1].(int)]
	}).(RedisClusterCreateIdentityTokenOutput)
}

type RedisClusterCreateIdentityTokenMapOutput struct{ *pulumi.OutputState }

func (RedisClusterCreateIdentityTokenMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*RedisClusterCreateIdentityToken)(nil)).Elem()
}

func (o RedisClusterCreateIdentityTokenMapOutput) ToRedisClusterCreateIdentityTokenMapOutput() RedisClusterCreateIdentityTokenMapOutput {
	return o
}

func (o RedisClusterCreateIdentityTokenMapOutput) ToRedisClusterCreateIdentityTokenMapOutputWithContext(ctx context.Context) RedisClusterCreateIdentityTokenMapOutput {
	return o
}

func (o RedisClusterCreateIdentityTokenMapOutput) MapIndex(k pulumi.StringInput) RedisClusterCreateIdentityTokenOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *RedisClusterCreateIdentityToken {
		return vs[0].(map[string]*RedisClusterCreateIdentityToken)[vs[1].(string)]
	}).(RedisClusterCreateIdentityTokenOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*RedisClusterCreateIdentityTokenInput)(nil)).Elem(), &RedisClusterCreateIdentityToken{})
	pulumi.RegisterInputType(reflect.TypeOf((*RedisClusterCreateIdentityTokenArrayInput)(nil)).Elem(), RedisClusterCreateIdentityTokenArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*RedisClusterCreateIdentityTokenMapInput)(nil)).Elem(), RedisClusterCreateIdentityTokenMap{})
	pulumi.RegisterOutputType(RedisClusterCreateIdentityTokenOutput{})
	pulumi.RegisterOutputType(RedisClusterCreateIdentityTokenArrayOutput{})
	pulumi.RegisterOutputType(RedisClusterCreateIdentityTokenMapOutput{})
}
