// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Database.inputs.GetAutonomousContainerDatabaseDataguardAssociationsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAutonomousContainerDatabaseDataguardAssociationsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAutonomousContainerDatabaseDataguardAssociationsPlainArgs Empty = new GetAutonomousContainerDatabaseDataguardAssociationsPlainArgs();

    /**
     * The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="autonomousContainerDatabaseId", required=true)
    private String autonomousContainerDatabaseId;

    /**
     * @return The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String autonomousContainerDatabaseId() {
        return this.autonomousContainerDatabaseId;
    }

    @Import(name="filters")
    private @Nullable List<GetAutonomousContainerDatabaseDataguardAssociationsFilter> filters;

    public Optional<List<GetAutonomousContainerDatabaseDataguardAssociationsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetAutonomousContainerDatabaseDataguardAssociationsPlainArgs() {}

    private GetAutonomousContainerDatabaseDataguardAssociationsPlainArgs(GetAutonomousContainerDatabaseDataguardAssociationsPlainArgs $) {
        this.autonomousContainerDatabaseId = $.autonomousContainerDatabaseId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAutonomousContainerDatabaseDataguardAssociationsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAutonomousContainerDatabaseDataguardAssociationsPlainArgs $;

        public Builder() {
            $ = new GetAutonomousContainerDatabaseDataguardAssociationsPlainArgs();
        }

        public Builder(GetAutonomousContainerDatabaseDataguardAssociationsPlainArgs defaults) {
            $ = new GetAutonomousContainerDatabaseDataguardAssociationsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param autonomousContainerDatabaseId The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder autonomousContainerDatabaseId(String autonomousContainerDatabaseId) {
            $.autonomousContainerDatabaseId = autonomousContainerDatabaseId;
            return this;
        }

        public Builder filters(@Nullable List<GetAutonomousContainerDatabaseDataguardAssociationsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetAutonomousContainerDatabaseDataguardAssociationsFilter... filters) {
            return filters(List.of(filters));
        }

        public GetAutonomousContainerDatabaseDataguardAssociationsPlainArgs build() {
            $.autonomousContainerDatabaseId = Objects.requireNonNull($.autonomousContainerDatabaseId, "expected parameter 'autonomousContainerDatabaseId' to be non-null");
            return $;
        }
    }

}