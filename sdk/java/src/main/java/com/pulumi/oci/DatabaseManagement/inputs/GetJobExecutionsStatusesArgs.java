// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.inputs.GetJobExecutionsStatusesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetJobExecutionsStatusesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetJobExecutionsStatusesArgs Empty = new GetJobExecutionsStatusesArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The end time of the time range to retrieve the status summary of job executions in UTC in ISO-8601 format, which is &#34;yyyy-MM-dd&#39;T&#39;hh:mm:ss.sss&#39;Z&#39;&#34;.
     * 
     */
    @Import(name="endTime", required=true)
    private Output<String> endTime;

    /**
     * @return The end time of the time range to retrieve the status summary of job executions in UTC in ISO-8601 format, which is &#34;yyyy-MM-dd&#39;T&#39;hh:mm:ss.sss&#39;Z&#39;&#34;.
     * 
     */
    public Output<String> endTime() {
        return this.endTime;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetJobExecutionsStatusesFilterArgs>> filters;

    public Optional<Output<List<GetJobExecutionsStatusesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The identifier of the resource.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The identifier of the resource.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database Group.
     * 
     */
    @Import(name="managedDatabaseGroupId")
    private @Nullable Output<String> managedDatabaseGroupId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database Group.
     * 
     */
    public Optional<Output<String>> managedDatabaseGroupId() {
        return Optional.ofNullable(this.managedDatabaseGroupId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    @Import(name="managedDatabaseId")
    private @Nullable Output<String> managedDatabaseId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    public Optional<Output<String>> managedDatabaseId() {
        return Optional.ofNullable(this.managedDatabaseId);
    }

    /**
     * A filter to return only resources that match the entire name.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A filter to return only resources that match the entire name.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The start time of the time range to retrieve the status summary of job executions in UTC in ISO-8601 format, which is &#34;yyyy-MM-dd&#39;T&#39;hh:mm:ss.sss&#39;Z&#39;&#34;.
     * 
     */
    @Import(name="startTime", required=true)
    private Output<String> startTime;

    /**
     * @return The start time of the time range to retrieve the status summary of job executions in UTC in ISO-8601 format, which is &#34;yyyy-MM-dd&#39;T&#39;hh:mm:ss.sss&#39;Z&#39;&#34;.
     * 
     */
    public Output<String> startTime() {
        return this.startTime;
    }

    private GetJobExecutionsStatusesArgs() {}

    private GetJobExecutionsStatusesArgs(GetJobExecutionsStatusesArgs $) {
        this.compartmentId = $.compartmentId;
        this.endTime = $.endTime;
        this.filters = $.filters;
        this.id = $.id;
        this.managedDatabaseGroupId = $.managedDatabaseGroupId;
        this.managedDatabaseId = $.managedDatabaseId;
        this.name = $.name;
        this.startTime = $.startTime;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetJobExecutionsStatusesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetJobExecutionsStatusesArgs $;

        public Builder() {
            $ = new GetJobExecutionsStatusesArgs();
        }

        public Builder(GetJobExecutionsStatusesArgs defaults) {
            $ = new GetJobExecutionsStatusesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param endTime The end time of the time range to retrieve the status summary of job executions in UTC in ISO-8601 format, which is &#34;yyyy-MM-dd&#39;T&#39;hh:mm:ss.sss&#39;Z&#39;&#34;.
         * 
         * @return builder
         * 
         */
        public Builder endTime(Output<String> endTime) {
            $.endTime = endTime;
            return this;
        }

        /**
         * @param endTime The end time of the time range to retrieve the status summary of job executions in UTC in ISO-8601 format, which is &#34;yyyy-MM-dd&#39;T&#39;hh:mm:ss.sss&#39;Z&#39;&#34;.
         * 
         * @return builder
         * 
         */
        public Builder endTime(String endTime) {
            return endTime(Output.of(endTime));
        }

        public Builder filters(@Nullable Output<List<GetJobExecutionsStatusesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetJobExecutionsStatusesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetJobExecutionsStatusesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id The identifier of the resource.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The identifier of the resource.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param managedDatabaseGroupId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database Group.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabaseGroupId(@Nullable Output<String> managedDatabaseGroupId) {
            $.managedDatabaseGroupId = managedDatabaseGroupId;
            return this;
        }

        /**
         * @param managedDatabaseGroupId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database Group.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabaseGroupId(String managedDatabaseGroupId) {
            return managedDatabaseGroupId(Output.of(managedDatabaseGroupId));
        }

        /**
         * @param managedDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabaseId(@Nullable Output<String> managedDatabaseId) {
            $.managedDatabaseId = managedDatabaseId;
            return this;
        }

        /**
         * @param managedDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabaseId(String managedDatabaseId) {
            return managedDatabaseId(Output.of(managedDatabaseId));
        }

        /**
         * @param name A filter to return only resources that match the entire name.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A filter to return only resources that match the entire name.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param startTime The start time of the time range to retrieve the status summary of job executions in UTC in ISO-8601 format, which is &#34;yyyy-MM-dd&#39;T&#39;hh:mm:ss.sss&#39;Z&#39;&#34;.
         * 
         * @return builder
         * 
         */
        public Builder startTime(Output<String> startTime) {
            $.startTime = startTime;
            return this;
        }

        /**
         * @param startTime The start time of the time range to retrieve the status summary of job executions in UTC in ISO-8601 format, which is &#34;yyyy-MM-dd&#39;T&#39;hh:mm:ss.sss&#39;Z&#39;&#34;.
         * 
         * @return builder
         * 
         */
        public Builder startTime(String startTime) {
            return startTime(Output.of(startTime));
        }

        public GetJobExecutionsStatusesArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetJobExecutionsStatusesArgs", "compartmentId");
            }
            if ($.endTime == null) {
                throw new MissingRequiredPropertyException("GetJobExecutionsStatusesArgs", "endTime");
            }
            if ($.startTime == null) {
                throw new MissingRequiredPropertyException("GetJobExecutionsStatusesArgs", "startTime");
            }
            return $;
        }
    }

}
