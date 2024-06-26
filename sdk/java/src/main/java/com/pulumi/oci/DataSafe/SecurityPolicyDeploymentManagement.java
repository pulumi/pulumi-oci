// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DataSafe.SecurityPolicyDeploymentManagementArgs;
import com.pulumi.oci.DataSafe.inputs.SecurityPolicyDeploymentManagementState;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

@ResourceType(type="oci:DataSafe/securityPolicyDeploymentManagement:SecurityPolicyDeploymentManagement")
public class SecurityPolicyDeploymentManagement extends com.pulumi.resources.CustomResource {
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    @Export(name="definedTags", refs={Map.class,String.class,Object.class}, tree="[0,1,2]")
    private Output<Map<String,Object>> definedTags;

    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    public Output<String> description() {
        return this.description;
    }
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    public Output<String> displayName() {
        return this.displayName;
    }
    @Export(name="freeformTags", refs={Map.class,String.class,Object.class}, tree="[0,1,2]")
    private Output<Map<String,Object>> freeformTags;

    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    @Export(name="securityPolicyId", refs={String.class}, tree="[0]")
    private Output<String> securityPolicyId;

    public Output<String> securityPolicyId() {
        return this.securityPolicyId;
    }
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    public Output<String> state() {
        return this.state;
    }
    @Export(name="systemTags", refs={Map.class,String.class,Object.class}, tree="[0,1,2]")
    private Output<Map<String,Object>> systemTags;

    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    @Export(name="targetId", refs={String.class}, tree="[0]")
    private Output<String> targetId;

    public Output<String> targetId() {
        return this.targetId;
    }
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public SecurityPolicyDeploymentManagement(String name) {
        this(name, SecurityPolicyDeploymentManagementArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public SecurityPolicyDeploymentManagement(String name, @Nullable SecurityPolicyDeploymentManagementArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public SecurityPolicyDeploymentManagement(String name, @Nullable SecurityPolicyDeploymentManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataSafe/securityPolicyDeploymentManagement:SecurityPolicyDeploymentManagement", name, args == null ? SecurityPolicyDeploymentManagementArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private SecurityPolicyDeploymentManagement(String name, Output<String> id, @Nullable SecurityPolicyDeploymentManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataSafe/securityPolicyDeploymentManagement:SecurityPolicyDeploymentManagement", name, state, makeResourceOptions(options, id));
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
    public static SecurityPolicyDeploymentManagement get(String name, Output<String> id, @Nullable SecurityPolicyDeploymentManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new SecurityPolicyDeploymentManagement(name, id, state, options);
    }
}
