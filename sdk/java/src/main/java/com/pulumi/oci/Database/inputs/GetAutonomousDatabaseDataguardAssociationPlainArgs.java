// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetAutonomousDatabaseDataguardAssociationPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAutonomousDatabaseDataguardAssociationPlainArgs Empty = new GetAutonomousDatabaseDataguardAssociationPlainArgs();

    /**
     * The Autonomous Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="autonomousDatabaseDataguardAssociationId", required=true)
    private String autonomousDatabaseDataguardAssociationId;

    /**
     * @return The Autonomous Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String autonomousDatabaseDataguardAssociationId() {
        return this.autonomousDatabaseDataguardAssociationId;
    }

    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="autonomousDatabaseId", required=true)
    private String autonomousDatabaseId;

    /**
     * @return The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String autonomousDatabaseId() {
        return this.autonomousDatabaseId;
    }

    private GetAutonomousDatabaseDataguardAssociationPlainArgs() {}

    private GetAutonomousDatabaseDataguardAssociationPlainArgs(GetAutonomousDatabaseDataguardAssociationPlainArgs $) {
        this.autonomousDatabaseDataguardAssociationId = $.autonomousDatabaseDataguardAssociationId;
        this.autonomousDatabaseId = $.autonomousDatabaseId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAutonomousDatabaseDataguardAssociationPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAutonomousDatabaseDataguardAssociationPlainArgs $;

        public Builder() {
            $ = new GetAutonomousDatabaseDataguardAssociationPlainArgs();
        }

        public Builder(GetAutonomousDatabaseDataguardAssociationPlainArgs defaults) {
            $ = new GetAutonomousDatabaseDataguardAssociationPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param autonomousDatabaseDataguardAssociationId The Autonomous Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder autonomousDatabaseDataguardAssociationId(String autonomousDatabaseDataguardAssociationId) {
            $.autonomousDatabaseDataguardAssociationId = autonomousDatabaseDataguardAssociationId;
            return this;
        }

        /**
         * @param autonomousDatabaseId The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder autonomousDatabaseId(String autonomousDatabaseId) {
            $.autonomousDatabaseId = autonomousDatabaseId;
            return this;
        }

        public GetAutonomousDatabaseDataguardAssociationPlainArgs build() {
            $.autonomousDatabaseDataguardAssociationId = Objects.requireNonNull($.autonomousDatabaseDataguardAssociationId, "expected parameter 'autonomousDatabaseDataguardAssociationId' to be non-null");
            $.autonomousDatabaseId = Objects.requireNonNull($.autonomousDatabaseId, "expected parameter 'autonomousDatabaseId' to be non-null");
            return $;
        }
    }

}