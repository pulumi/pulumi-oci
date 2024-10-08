// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.CloudVmClusterIormConfigDbPlanArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CloudVmClusterIormConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final CloudVmClusterIormConfigArgs Empty = new CloudVmClusterIormConfigArgs();

    /**
     * The Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="cloudVmClusterId", required=true)
    private Output<String> cloudVmClusterId;

    /**
     * @return The Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> cloudVmClusterId() {
        return this.cloudVmClusterId;
    }

    /**
     * (Updatable) Array of IORM Setting for all the database in this Cloud Vm Cluster
     * 
     */
    @Import(name="dbPlans", required=true)
    private Output<List<CloudVmClusterIormConfigDbPlanArgs>> dbPlans;

    /**
     * @return (Updatable) Array of IORM Setting for all the database in this Cloud Vm Cluster
     * 
     */
    public Output<List<CloudVmClusterIormConfigDbPlanArgs>> dbPlans() {
        return this.dbPlans;
    }

    /**
     * (Updatable) Value for the IORM objective Default is &#34;Auto&#34;
     * 
     */
    @Import(name="objective")
    private @Nullable Output<String> objective;

    /**
     * @return (Updatable) Value for the IORM objective Default is &#34;Auto&#34;
     * 
     */
    public Optional<Output<String>> objective() {
        return Optional.ofNullable(this.objective);
    }

    private CloudVmClusterIormConfigArgs() {}

    private CloudVmClusterIormConfigArgs(CloudVmClusterIormConfigArgs $) {
        this.cloudVmClusterId = $.cloudVmClusterId;
        this.dbPlans = $.dbPlans;
        this.objective = $.objective;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CloudVmClusterIormConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CloudVmClusterIormConfigArgs $;

        public Builder() {
            $ = new CloudVmClusterIormConfigArgs();
        }

        public Builder(CloudVmClusterIormConfigArgs defaults) {
            $ = new CloudVmClusterIormConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param cloudVmClusterId The Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder cloudVmClusterId(Output<String> cloudVmClusterId) {
            $.cloudVmClusterId = cloudVmClusterId;
            return this;
        }

        /**
         * @param cloudVmClusterId The Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder cloudVmClusterId(String cloudVmClusterId) {
            return cloudVmClusterId(Output.of(cloudVmClusterId));
        }

        /**
         * @param dbPlans (Updatable) Array of IORM Setting for all the database in this Cloud Vm Cluster
         * 
         * @return builder
         * 
         */
        public Builder dbPlans(Output<List<CloudVmClusterIormConfigDbPlanArgs>> dbPlans) {
            $.dbPlans = dbPlans;
            return this;
        }

        /**
         * @param dbPlans (Updatable) Array of IORM Setting for all the database in this Cloud Vm Cluster
         * 
         * @return builder
         * 
         */
        public Builder dbPlans(List<CloudVmClusterIormConfigDbPlanArgs> dbPlans) {
            return dbPlans(Output.of(dbPlans));
        }

        /**
         * @param dbPlans (Updatable) Array of IORM Setting for all the database in this Cloud Vm Cluster
         * 
         * @return builder
         * 
         */
        public Builder dbPlans(CloudVmClusterIormConfigDbPlanArgs... dbPlans) {
            return dbPlans(List.of(dbPlans));
        }

        /**
         * @param objective (Updatable) Value for the IORM objective Default is &#34;Auto&#34;
         * 
         * @return builder
         * 
         */
        public Builder objective(@Nullable Output<String> objective) {
            $.objective = objective;
            return this;
        }

        /**
         * @param objective (Updatable) Value for the IORM objective Default is &#34;Auto&#34;
         * 
         * @return builder
         * 
         */
        public Builder objective(String objective) {
            return objective(Output.of(objective));
        }

        public CloudVmClusterIormConfigArgs build() {
            if ($.cloudVmClusterId == null) {
                throw new MissingRequiredPropertyException("CloudVmClusterIormConfigArgs", "cloudVmClusterId");
            }
            if ($.dbPlans == null) {
                throw new MissingRequiredPropertyException("CloudVmClusterIormConfigArgs", "dbPlans");
            }
            return $;
        }
    }

}
