// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetScheduledJobsScheduledJobCollectionItemOperationManageModuleStreamsDetailDisable {
    /**
     * @return The name of a module.
     * 
     */
    private String moduleName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source that contains the module stream.
     * 
     */
    private String softwareSourceId;
    /**
     * @return The name of a stream of the specified module.
     * 
     */
    private String streamName;

    private GetScheduledJobsScheduledJobCollectionItemOperationManageModuleStreamsDetailDisable() {}
    /**
     * @return The name of a module.
     * 
     */
    public String moduleName() {
        return this.moduleName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source that contains the module stream.
     * 
     */
    public String softwareSourceId() {
        return this.softwareSourceId;
    }
    /**
     * @return The name of a stream of the specified module.
     * 
     */
    public String streamName() {
        return this.streamName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetScheduledJobsScheduledJobCollectionItemOperationManageModuleStreamsDetailDisable defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String moduleName;
        private String softwareSourceId;
        private String streamName;
        public Builder() {}
        public Builder(GetScheduledJobsScheduledJobCollectionItemOperationManageModuleStreamsDetailDisable defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.moduleName = defaults.moduleName;
    	      this.softwareSourceId = defaults.softwareSourceId;
    	      this.streamName = defaults.streamName;
        }

        @CustomType.Setter
        public Builder moduleName(String moduleName) {
            if (moduleName == null) {
              throw new MissingRequiredPropertyException("GetScheduledJobsScheduledJobCollectionItemOperationManageModuleStreamsDetailDisable", "moduleName");
            }
            this.moduleName = moduleName;
            return this;
        }
        @CustomType.Setter
        public Builder softwareSourceId(String softwareSourceId) {
            if (softwareSourceId == null) {
              throw new MissingRequiredPropertyException("GetScheduledJobsScheduledJobCollectionItemOperationManageModuleStreamsDetailDisable", "softwareSourceId");
            }
            this.softwareSourceId = softwareSourceId;
            return this;
        }
        @CustomType.Setter
        public Builder streamName(String streamName) {
            if (streamName == null) {
              throw new MissingRequiredPropertyException("GetScheduledJobsScheduledJobCollectionItemOperationManageModuleStreamsDetailDisable", "streamName");
            }
            this.streamName = streamName;
            return this;
        }
        public GetScheduledJobsScheduledJobCollectionItemOperationManageModuleStreamsDetailDisable build() {
            final var _resultValue = new GetScheduledJobsScheduledJobCollectionItemOperationManageModuleStreamsDetailDisable();
            _resultValue.moduleName = moduleName;
            _resultValue.softwareSourceId = softwareSourceId;
            _resultValue.streamName = streamName;
            return _resultValue;
        }
    }
}
