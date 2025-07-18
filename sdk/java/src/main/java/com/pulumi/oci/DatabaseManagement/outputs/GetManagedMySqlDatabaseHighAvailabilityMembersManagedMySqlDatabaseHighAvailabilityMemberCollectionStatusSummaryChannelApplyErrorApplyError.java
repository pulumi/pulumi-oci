// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelApplyErrorApplyErrorWorkerError;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelApplyErrorApplyError {
    /**
     * @return The error message of the most recent error that caused the I/O thread to stop.
     * 
     */
    private String lastErrorMessage;
    /**
     * @return The error number of the most recent error that caused the I/O thread to stop.
     * 
     */
    private Integer lastErrorNumber;
    /**
     * @return The timestamp when the most recent I/O error occurred.
     * 
     */
    private String timeLastError;
    /**
     * @return A list of MySqlApplyErrorWorker records.
     * 
     */
    private List<GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelApplyErrorApplyErrorWorkerError> workerErrors;

    private GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelApplyErrorApplyError() {}
    /**
     * @return The error message of the most recent error that caused the I/O thread to stop.
     * 
     */
    public String lastErrorMessage() {
        return this.lastErrorMessage;
    }
    /**
     * @return The error number of the most recent error that caused the I/O thread to stop.
     * 
     */
    public Integer lastErrorNumber() {
        return this.lastErrorNumber;
    }
    /**
     * @return The timestamp when the most recent I/O error occurred.
     * 
     */
    public String timeLastError() {
        return this.timeLastError;
    }
    /**
     * @return A list of MySqlApplyErrorWorker records.
     * 
     */
    public List<GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelApplyErrorApplyErrorWorkerError> workerErrors() {
        return this.workerErrors;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelApplyErrorApplyError defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String lastErrorMessage;
        private Integer lastErrorNumber;
        private String timeLastError;
        private List<GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelApplyErrorApplyErrorWorkerError> workerErrors;
        public Builder() {}
        public Builder(GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelApplyErrorApplyError defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.lastErrorMessage = defaults.lastErrorMessage;
    	      this.lastErrorNumber = defaults.lastErrorNumber;
    	      this.timeLastError = defaults.timeLastError;
    	      this.workerErrors = defaults.workerErrors;
        }

        @CustomType.Setter
        public Builder lastErrorMessage(String lastErrorMessage) {
            if (lastErrorMessage == null) {
              throw new MissingRequiredPropertyException("GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelApplyErrorApplyError", "lastErrorMessage");
            }
            this.lastErrorMessage = lastErrorMessage;
            return this;
        }
        @CustomType.Setter
        public Builder lastErrorNumber(Integer lastErrorNumber) {
            if (lastErrorNumber == null) {
              throw new MissingRequiredPropertyException("GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelApplyErrorApplyError", "lastErrorNumber");
            }
            this.lastErrorNumber = lastErrorNumber;
            return this;
        }
        @CustomType.Setter
        public Builder timeLastError(String timeLastError) {
            if (timeLastError == null) {
              throw new MissingRequiredPropertyException("GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelApplyErrorApplyError", "timeLastError");
            }
            this.timeLastError = timeLastError;
            return this;
        }
        @CustomType.Setter
        public Builder workerErrors(List<GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelApplyErrorApplyErrorWorkerError> workerErrors) {
            if (workerErrors == null) {
              throw new MissingRequiredPropertyException("GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelApplyErrorApplyError", "workerErrors");
            }
            this.workerErrors = workerErrors;
            return this;
        }
        public Builder workerErrors(GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelApplyErrorApplyErrorWorkerError... workerErrors) {
            return workerErrors(List.of(workerErrors));
        }
        public GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelApplyErrorApplyError build() {
            final var _resultValue = new GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelApplyErrorApplyError();
            _resultValue.lastErrorMessage = lastErrorMessage;
            _resultValue.lastErrorNumber = lastErrorNumber;
            _resultValue.timeLastError = timeLastError;
            _resultValue.workerErrors = workerErrors;
            return _resultValue;
        }
    }
}
