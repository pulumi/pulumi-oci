// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Database.AutonomousContainerDatabaseDataguardRoleChangeArgs;
import com.pulumi.oci.Database.inputs.AutonomousContainerDatabaseDataguardRoleChangeState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.Optional;
import javax.annotation.Nullable;

@ResourceType(type="oci:Database/autonomousContainerDatabaseDataguardRoleChange:AutonomousContainerDatabaseDataguardRoleChange")
public class AutonomousContainerDatabaseDataguardRoleChange extends com.pulumi.resources.CustomResource {
    @Export(name="autonomousContainerDatabaseDataguardAssociationId", refs={String.class}, tree="[0]")
    private Output<String> autonomousContainerDatabaseDataguardAssociationId;

    public Output<String> autonomousContainerDatabaseDataguardAssociationId() {
        return this.autonomousContainerDatabaseDataguardAssociationId;
    }
    @Export(name="autonomousContainerDatabaseId", refs={String.class}, tree="[0]")
    private Output<String> autonomousContainerDatabaseId;

    public Output<String> autonomousContainerDatabaseId() {
        return this.autonomousContainerDatabaseId;
    }
    @Export(name="connectionStringsType", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> connectionStringsType;

    public Output<Optional<String>> connectionStringsType() {
        return Codegen.optional(this.connectionStringsType);
    }
    @Export(name="role", refs={String.class}, tree="[0]")
    private Output<String> role;

    public Output<String> role() {
        return this.role;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public AutonomousContainerDatabaseDataguardRoleChange(java.lang.String name) {
        this(name, AutonomousContainerDatabaseDataguardRoleChangeArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public AutonomousContainerDatabaseDataguardRoleChange(java.lang.String name, AutonomousContainerDatabaseDataguardRoleChangeArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public AutonomousContainerDatabaseDataguardRoleChange(java.lang.String name, AutonomousContainerDatabaseDataguardRoleChangeArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/autonomousContainerDatabaseDataguardRoleChange:AutonomousContainerDatabaseDataguardRoleChange", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private AutonomousContainerDatabaseDataguardRoleChange(java.lang.String name, Output<java.lang.String> id, @Nullable AutonomousContainerDatabaseDataguardRoleChangeState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/autonomousContainerDatabaseDataguardRoleChange:AutonomousContainerDatabaseDataguardRoleChange", name, state, makeResourceOptions(options, id), false);
    }

    private static AutonomousContainerDatabaseDataguardRoleChangeArgs makeArgs(AutonomousContainerDatabaseDataguardRoleChangeArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? AutonomousContainerDatabaseDataguardRoleChangeArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
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
    public static AutonomousContainerDatabaseDataguardRoleChange get(java.lang.String name, Output<java.lang.String> id, @Nullable AutonomousContainerDatabaseDataguardRoleChangeState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new AutonomousContainerDatabaseDataguardRoleChange(name, id, state, options);
    }
}
