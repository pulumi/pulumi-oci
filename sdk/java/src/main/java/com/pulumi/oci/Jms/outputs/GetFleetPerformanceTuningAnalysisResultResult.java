// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetFleetPerformanceTuningAnalysisResultResult {
    /**
     * @return The OCID of the application for which the report has been generated.
     * 
     */
    private String applicationId;
    /**
     * @return The internal identifier of the application installation for which the report has been generated.
     * 
     */
    private String applicationInstallationId;
    /**
     * @return The installation path of the application for which the report has been generated.
     * 
     */
    private String applicationInstallationPath;
    /**
     * @return The name of the application for which the report has been generated.
     * 
     */
    private String applicationName;
    /**
     * @return The Object Storage bucket name of this analysis result.
     * 
     */
    private String bucket;
    /**
     * @return The fleet OCID.
     * 
     */
    private String fleetId;
    /**
     * @return The hostname of the managed instance.
     * 
     */
    private String hostName;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The managed instance OCID.
     * 
     */
    private String managedInstanceId;
    /**
     * @return The Object Storage namespace of this analysis result.
     * 
     */
    private String namespace;
    /**
     * @return The Object Storage object name of this analysis result.
     * 
     */
    private String object;
    private String performanceTuningAnalysisResultId;
    /**
     * @return Result of the analysis based on whether warnings have been found or not.
     * 
     */
    private String result;
    /**
     * @return The time the result is compiled.
     * 
     */
    private String timeCreated;
    /**
     * @return The time the JFR recording has finished.
     * 
     */
    private String timeFinished;
    /**
     * @return The time the JFR recording has started.
     * 
     */
    private String timeStarted;
    /**
     * @return Total number of warnings reported by the analysis.
     * 
     */
    private Integer warningCount;
    /**
     * @return The OCID of the work request to start the analysis.
     * 
     */
    private String workRequestId;

    private GetFleetPerformanceTuningAnalysisResultResult() {}
    /**
     * @return The OCID of the application for which the report has been generated.
     * 
     */
    public String applicationId() {
        return this.applicationId;
    }
    /**
     * @return The internal identifier of the application installation for which the report has been generated.
     * 
     */
    public String applicationInstallationId() {
        return this.applicationInstallationId;
    }
    /**
     * @return The installation path of the application for which the report has been generated.
     * 
     */
    public String applicationInstallationPath() {
        return this.applicationInstallationPath;
    }
    /**
     * @return The name of the application for which the report has been generated.
     * 
     */
    public String applicationName() {
        return this.applicationName;
    }
    /**
     * @return The Object Storage bucket name of this analysis result.
     * 
     */
    public String bucket() {
        return this.bucket;
    }
    /**
     * @return The fleet OCID.
     * 
     */
    public String fleetId() {
        return this.fleetId;
    }
    /**
     * @return The hostname of the managed instance.
     * 
     */
    public String hostName() {
        return this.hostName;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The managed instance OCID.
     * 
     */
    public String managedInstanceId() {
        return this.managedInstanceId;
    }
    /**
     * @return The Object Storage namespace of this analysis result.
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return The Object Storage object name of this analysis result.
     * 
     */
    public String object() {
        return this.object;
    }
    public String performanceTuningAnalysisResultId() {
        return this.performanceTuningAnalysisResultId;
    }
    /**
     * @return Result of the analysis based on whether warnings have been found or not.
     * 
     */
    public String result() {
        return this.result;
    }
    /**
     * @return The time the result is compiled.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the JFR recording has finished.
     * 
     */
    public String timeFinished() {
        return this.timeFinished;
    }
    /**
     * @return The time the JFR recording has started.
     * 
     */
    public String timeStarted() {
        return this.timeStarted;
    }
    /**
     * @return Total number of warnings reported by the analysis.
     * 
     */
    public Integer warningCount() {
        return this.warningCount;
    }
    /**
     * @return The OCID of the work request to start the analysis.
     * 
     */
    public String workRequestId() {
        return this.workRequestId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFleetPerformanceTuningAnalysisResultResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String applicationId;
        private String applicationInstallationId;
        private String applicationInstallationPath;
        private String applicationName;
        private String bucket;
        private String fleetId;
        private String hostName;
        private String id;
        private String managedInstanceId;
        private String namespace;
        private String object;
        private String performanceTuningAnalysisResultId;
        private String result;
        private String timeCreated;
        private String timeFinished;
        private String timeStarted;
        private Integer warningCount;
        private String workRequestId;
        public Builder() {}
        public Builder(GetFleetPerformanceTuningAnalysisResultResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicationId = defaults.applicationId;
    	      this.applicationInstallationId = defaults.applicationInstallationId;
    	      this.applicationInstallationPath = defaults.applicationInstallationPath;
    	      this.applicationName = defaults.applicationName;
    	      this.bucket = defaults.bucket;
    	      this.fleetId = defaults.fleetId;
    	      this.hostName = defaults.hostName;
    	      this.id = defaults.id;
    	      this.managedInstanceId = defaults.managedInstanceId;
    	      this.namespace = defaults.namespace;
    	      this.object = defaults.object;
    	      this.performanceTuningAnalysisResultId = defaults.performanceTuningAnalysisResultId;
    	      this.result = defaults.result;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeFinished = defaults.timeFinished;
    	      this.timeStarted = defaults.timeStarted;
    	      this.warningCount = defaults.warningCount;
    	      this.workRequestId = defaults.workRequestId;
        }

        @CustomType.Setter
        public Builder applicationId(String applicationId) {
            if (applicationId == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "applicationId");
            }
            this.applicationId = applicationId;
            return this;
        }
        @CustomType.Setter
        public Builder applicationInstallationId(String applicationInstallationId) {
            if (applicationInstallationId == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "applicationInstallationId");
            }
            this.applicationInstallationId = applicationInstallationId;
            return this;
        }
        @CustomType.Setter
        public Builder applicationInstallationPath(String applicationInstallationPath) {
            if (applicationInstallationPath == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "applicationInstallationPath");
            }
            this.applicationInstallationPath = applicationInstallationPath;
            return this;
        }
        @CustomType.Setter
        public Builder applicationName(String applicationName) {
            if (applicationName == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "applicationName");
            }
            this.applicationName = applicationName;
            return this;
        }
        @CustomType.Setter
        public Builder bucket(String bucket) {
            if (bucket == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "bucket");
            }
            this.bucket = bucket;
            return this;
        }
        @CustomType.Setter
        public Builder fleetId(String fleetId) {
            if (fleetId == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "fleetId");
            }
            this.fleetId = fleetId;
            return this;
        }
        @CustomType.Setter
        public Builder hostName(String hostName) {
            if (hostName == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "hostName");
            }
            this.hostName = hostName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder managedInstanceId(String managedInstanceId) {
            if (managedInstanceId == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "managedInstanceId");
            }
            this.managedInstanceId = managedInstanceId;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            if (namespace == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "namespace");
            }
            this.namespace = namespace;
            return this;
        }
        @CustomType.Setter
        public Builder object(String object) {
            if (object == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "object");
            }
            this.object = object;
            return this;
        }
        @CustomType.Setter
        public Builder performanceTuningAnalysisResultId(String performanceTuningAnalysisResultId) {
            if (performanceTuningAnalysisResultId == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "performanceTuningAnalysisResultId");
            }
            this.performanceTuningAnalysisResultId = performanceTuningAnalysisResultId;
            return this;
        }
        @CustomType.Setter
        public Builder result(String result) {
            if (result == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "result");
            }
            this.result = result;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeFinished(String timeFinished) {
            if (timeFinished == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "timeFinished");
            }
            this.timeFinished = timeFinished;
            return this;
        }
        @CustomType.Setter
        public Builder timeStarted(String timeStarted) {
            if (timeStarted == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "timeStarted");
            }
            this.timeStarted = timeStarted;
            return this;
        }
        @CustomType.Setter
        public Builder warningCount(Integer warningCount) {
            if (warningCount == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "warningCount");
            }
            this.warningCount = warningCount;
            return this;
        }
        @CustomType.Setter
        public Builder workRequestId(String workRequestId) {
            if (workRequestId == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultResult", "workRequestId");
            }
            this.workRequestId = workRequestId;
            return this;
        }
        public GetFleetPerformanceTuningAnalysisResultResult build() {
            final var _resultValue = new GetFleetPerformanceTuningAnalysisResultResult();
            _resultValue.applicationId = applicationId;
            _resultValue.applicationInstallationId = applicationInstallationId;
            _resultValue.applicationInstallationPath = applicationInstallationPath;
            _resultValue.applicationName = applicationName;
            _resultValue.bucket = bucket;
            _resultValue.fleetId = fleetId;
            _resultValue.hostName = hostName;
            _resultValue.id = id;
            _resultValue.managedInstanceId = managedInstanceId;
            _resultValue.namespace = namespace;
            _resultValue.object = object;
            _resultValue.performanceTuningAnalysisResultId = performanceTuningAnalysisResultId;
            _resultValue.result = result;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeFinished = timeFinished;
            _resultValue.timeStarted = timeStarted;
            _resultValue.warningCount = warningCount;
            _resultValue.workRequestId = workRequestId;
            return _resultValue;
        }
    }
}
