// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetWorkspaceApplicationScheduleArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetWorkspaceApplicationScheduleArgs Empty = new GetWorkspaceApplicationScheduleArgs();

    /**
     * The application key.
     * 
     */
    @Import(name="applicationKey", required=true)
    private Output<String> applicationKey;

    /**
     * @return The application key.
     * 
     */
    public Output<String> applicationKey() {
        return this.applicationKey;
    }

    /**
     * Schedule Key
     * 
     */
    @Import(name="scheduleKey", required=true)
    private Output<String> scheduleKey;

    /**
     * @return Schedule Key
     * 
     */
    public Output<String> scheduleKey() {
        return this.scheduleKey;
    }

    /**
     * The workspace ID.
     * 
     */
    @Import(name="workspaceId", required=true)
    private Output<String> workspaceId;

    /**
     * @return The workspace ID.
     * 
     */
    public Output<String> workspaceId() {
        return this.workspaceId;
    }

    private GetWorkspaceApplicationScheduleArgs() {}

    private GetWorkspaceApplicationScheduleArgs(GetWorkspaceApplicationScheduleArgs $) {
        this.applicationKey = $.applicationKey;
        this.scheduleKey = $.scheduleKey;
        this.workspaceId = $.workspaceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetWorkspaceApplicationScheduleArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetWorkspaceApplicationScheduleArgs $;

        public Builder() {
            $ = new GetWorkspaceApplicationScheduleArgs();
        }

        public Builder(GetWorkspaceApplicationScheduleArgs defaults) {
            $ = new GetWorkspaceApplicationScheduleArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param applicationKey The application key.
         * 
         * @return builder
         * 
         */
        public Builder applicationKey(Output<String> applicationKey) {
            $.applicationKey = applicationKey;
            return this;
        }

        /**
         * @param applicationKey The application key.
         * 
         * @return builder
         * 
         */
        public Builder applicationKey(String applicationKey) {
            return applicationKey(Output.of(applicationKey));
        }

        /**
         * @param scheduleKey Schedule Key
         * 
         * @return builder
         * 
         */
        public Builder scheduleKey(Output<String> scheduleKey) {
            $.scheduleKey = scheduleKey;
            return this;
        }

        /**
         * @param scheduleKey Schedule Key
         * 
         * @return builder
         * 
         */
        public Builder scheduleKey(String scheduleKey) {
            return scheduleKey(Output.of(scheduleKey));
        }

        /**
         * @param workspaceId The workspace ID.
         * 
         * @return builder
         * 
         */
        public Builder workspaceId(Output<String> workspaceId) {
            $.workspaceId = workspaceId;
            return this;
        }

        /**
         * @param workspaceId The workspace ID.
         * 
         * @return builder
         * 
         */
        public Builder workspaceId(String workspaceId) {
            return workspaceId(Output.of(workspaceId));
        }

        public GetWorkspaceApplicationScheduleArgs build() {
            if ($.applicationKey == null) {
                throw new MissingRequiredPropertyException("GetWorkspaceApplicationScheduleArgs", "applicationKey");
            }
            if ($.scheduleKey == null) {
                throw new MissingRequiredPropertyException("GetWorkspaceApplicationScheduleArgs", "scheduleKey");
            }
            if ($.workspaceId == null) {
                throw new MissingRequiredPropertyException("GetWorkspaceApplicationScheduleArgs", "workspaceId");
            }
            return $;
        }
    }

}
