// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetAutonomousContainerDatabaseResourceUsagePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAutonomousContainerDatabaseResourceUsagePlainArgs Empty = new GetAutonomousContainerDatabaseResourceUsagePlainArgs();

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

    private GetAutonomousContainerDatabaseResourceUsagePlainArgs() {}

    private GetAutonomousContainerDatabaseResourceUsagePlainArgs(GetAutonomousContainerDatabaseResourceUsagePlainArgs $) {
        this.autonomousContainerDatabaseId = $.autonomousContainerDatabaseId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAutonomousContainerDatabaseResourceUsagePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAutonomousContainerDatabaseResourceUsagePlainArgs $;

        public Builder() {
            $ = new GetAutonomousContainerDatabaseResourceUsagePlainArgs();
        }

        public Builder(GetAutonomousContainerDatabaseResourceUsagePlainArgs defaults) {
            $ = new GetAutonomousContainerDatabaseResourceUsagePlainArgs(Objects.requireNonNull(defaults));
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

        public GetAutonomousContainerDatabaseResourceUsagePlainArgs build() {
            if ($.autonomousContainerDatabaseId == null) {
                throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseResourceUsagePlainArgs", "autonomousContainerDatabaseId");
            }
            return $;
        }
    }

}
