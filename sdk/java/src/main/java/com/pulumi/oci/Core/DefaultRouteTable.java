// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Core.DefaultRouteTableArgs;
import com.pulumi.oci.Core.inputs.DefaultRouteTableState;
import com.pulumi.oci.Core.outputs.DefaultRouteTableRouteRule;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;

@ResourceType(type="oci:Core/defaultRouteTable:DefaultRouteTable")
public class DefaultRouteTable extends com.pulumi.resources.CustomResource {
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    public Output<String> displayName() {
        return this.displayName;
    }
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    @Export(name="manageDefaultResourceId", type=String.class, parameters={})
    private Output<String> manageDefaultResourceId;

    public Output<String> manageDefaultResourceId() {
        return this.manageDefaultResourceId;
    }
    @Export(name="routeRules", type=List.class, parameters={DefaultRouteTableRouteRule.class})
    private Output</* @Nullable */ List<DefaultRouteTableRouteRule>> routeRules;

    public Output<Optional<List<DefaultRouteTableRouteRule>>> routeRules() {
        return Codegen.optional(this.routeRules);
    }
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    public Output<String> state() {
        return this.state;
    }
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    public Output<String> timeCreated() {
        return this.timeCreated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DefaultRouteTable(String name) {
        this(name, DefaultRouteTableArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DefaultRouteTable(String name, DefaultRouteTableArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DefaultRouteTable(String name, DefaultRouteTableArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/defaultRouteTable:DefaultRouteTable", name, args == null ? DefaultRouteTableArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private DefaultRouteTable(String name, Output<String> id, @Nullable DefaultRouteTableState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/defaultRouteTable:DefaultRouteTable", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static DefaultRouteTable get(String name, Output<String> id, @Nullable DefaultRouteTableState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DefaultRouteTable(name, id, state, options);
    }
}