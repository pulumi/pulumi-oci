// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AutonomousContainerDatabaseDataguardRoleChangeState extends com.pulumi.resources.ResourceArgs {

    public static final AutonomousContainerDatabaseDataguardRoleChangeState Empty = new AutonomousContainerDatabaseDataguardRoleChangeState();

    @Import(name="autonomousContainerDatabaseDataguardAssociationId")
    private @Nullable Output<String> autonomousContainerDatabaseDataguardAssociationId;

    public Optional<Output<String>> autonomousContainerDatabaseDataguardAssociationId() {
        return Optional.ofNullable(this.autonomousContainerDatabaseDataguardAssociationId);
    }

    @Import(name="autonomousContainerDatabaseId")
    private @Nullable Output<String> autonomousContainerDatabaseId;

    public Optional<Output<String>> autonomousContainerDatabaseId() {
        return Optional.ofNullable(this.autonomousContainerDatabaseId);
    }

    @Import(name="connectionStringsType")
    private @Nullable Output<String> connectionStringsType;

    public Optional<Output<String>> connectionStringsType() {
        return Optional.ofNullable(this.connectionStringsType);
    }

    @Import(name="role")
    private @Nullable Output<String> role;

    public Optional<Output<String>> role() {
        return Optional.ofNullable(this.role);
    }

    private AutonomousContainerDatabaseDataguardRoleChangeState() {}

    private AutonomousContainerDatabaseDataguardRoleChangeState(AutonomousContainerDatabaseDataguardRoleChangeState $) {
        this.autonomousContainerDatabaseDataguardAssociationId = $.autonomousContainerDatabaseDataguardAssociationId;
        this.autonomousContainerDatabaseId = $.autonomousContainerDatabaseId;
        this.connectionStringsType = $.connectionStringsType;
        this.role = $.role;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AutonomousContainerDatabaseDataguardRoleChangeState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AutonomousContainerDatabaseDataguardRoleChangeState $;

        public Builder() {
            $ = new AutonomousContainerDatabaseDataguardRoleChangeState();
        }

        public Builder(AutonomousContainerDatabaseDataguardRoleChangeState defaults) {
            $ = new AutonomousContainerDatabaseDataguardRoleChangeState(Objects.requireNonNull(defaults));
        }

        public Builder autonomousContainerDatabaseDataguardAssociationId(@Nullable Output<String> autonomousContainerDatabaseDataguardAssociationId) {
            $.autonomousContainerDatabaseDataguardAssociationId = autonomousContainerDatabaseDataguardAssociationId;
            return this;
        }

        public Builder autonomousContainerDatabaseDataguardAssociationId(String autonomousContainerDatabaseDataguardAssociationId) {
            return autonomousContainerDatabaseDataguardAssociationId(Output.of(autonomousContainerDatabaseDataguardAssociationId));
        }

        public Builder autonomousContainerDatabaseId(@Nullable Output<String> autonomousContainerDatabaseId) {
            $.autonomousContainerDatabaseId = autonomousContainerDatabaseId;
            return this;
        }

        public Builder autonomousContainerDatabaseId(String autonomousContainerDatabaseId) {
            return autonomousContainerDatabaseId(Output.of(autonomousContainerDatabaseId));
        }

        public Builder connectionStringsType(@Nullable Output<String> connectionStringsType) {
            $.connectionStringsType = connectionStringsType;
            return this;
        }

        public Builder connectionStringsType(String connectionStringsType) {
            return connectionStringsType(Output.of(connectionStringsType));
        }

        public Builder role(@Nullable Output<String> role) {
            $.role = role;
            return this;
        }

        public Builder role(String role) {
            return role(Output.of(role));
        }

        public AutonomousContainerDatabaseDataguardRoleChangeState build() {
            return $;
        }
    }

}