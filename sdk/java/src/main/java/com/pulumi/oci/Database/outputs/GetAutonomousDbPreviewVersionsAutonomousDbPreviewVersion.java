// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAutonomousDbPreviewVersionsAutonomousDbPreviewVersion {
    /**
     * @return The Autonomous Database workload type. The following values are valid:
     * * OLTP - indicates an Autonomous Transaction Processing database
     * * DW - indicates an Autonomous Data Warehouse database
     * * AJD - indicates an Autonomous JSON Database
     * * APEX - indicates an Autonomous Database with the Oracle APEX Application Development workload type.
     * 
     */
    private final String dbWorkload;
    /**
     * @return A URL that points to a detailed description of the preview version.
     * 
     */
    private final String details;
    /**
     * @return The date and time when the preview version availability begins.
     * 
     */
    private final String timePreviewBegin;
    /**
     * @return The date and time when the preview version availability ends.
     * 
     */
    private final String timePreviewEnd;
    /**
     * @return A valid Autonomous Database preview version.
     * 
     */
    private final String version;

    @CustomType.Constructor
    private GetAutonomousDbPreviewVersionsAutonomousDbPreviewVersion(
        @CustomType.Parameter("dbWorkload") String dbWorkload,
        @CustomType.Parameter("details") String details,
        @CustomType.Parameter("timePreviewBegin") String timePreviewBegin,
        @CustomType.Parameter("timePreviewEnd") String timePreviewEnd,
        @CustomType.Parameter("version") String version) {
        this.dbWorkload = dbWorkload;
        this.details = details;
        this.timePreviewBegin = timePreviewBegin;
        this.timePreviewEnd = timePreviewEnd;
        this.version = version;
    }

    /**
     * @return The Autonomous Database workload type. The following values are valid:
     * * OLTP - indicates an Autonomous Transaction Processing database
     * * DW - indicates an Autonomous Data Warehouse database
     * * AJD - indicates an Autonomous JSON Database
     * * APEX - indicates an Autonomous Database with the Oracle APEX Application Development workload type.
     * 
     */
    public String dbWorkload() {
        return this.dbWorkload;
    }
    /**
     * @return A URL that points to a detailed description of the preview version.
     * 
     */
    public String details() {
        return this.details;
    }
    /**
     * @return The date and time when the preview version availability begins.
     * 
     */
    public String timePreviewBegin() {
        return this.timePreviewBegin;
    }
    /**
     * @return The date and time when the preview version availability ends.
     * 
     */
    public String timePreviewEnd() {
        return this.timePreviewEnd;
    }
    /**
     * @return A valid Autonomous Database preview version.
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousDbPreviewVersionsAutonomousDbPreviewVersion defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String dbWorkload;
        private String details;
        private String timePreviewBegin;
        private String timePreviewEnd;
        private String version;

        public Builder() {
    	      // Empty
        }

        public Builder(GetAutonomousDbPreviewVersionsAutonomousDbPreviewVersion defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dbWorkload = defaults.dbWorkload;
    	      this.details = defaults.details;
    	      this.timePreviewBegin = defaults.timePreviewBegin;
    	      this.timePreviewEnd = defaults.timePreviewEnd;
    	      this.version = defaults.version;
        }

        public Builder dbWorkload(String dbWorkload) {
            this.dbWorkload = Objects.requireNonNull(dbWorkload);
            return this;
        }
        public Builder details(String details) {
            this.details = Objects.requireNonNull(details);
            return this;
        }
        public Builder timePreviewBegin(String timePreviewBegin) {
            this.timePreviewBegin = Objects.requireNonNull(timePreviewBegin);
            return this;
        }
        public Builder timePreviewEnd(String timePreviewEnd) {
            this.timePreviewEnd = Objects.requireNonNull(timePreviewEnd);
            return this;
        }
        public Builder version(String version) {
            this.version = Objects.requireNonNull(version);
            return this;
        }        public GetAutonomousDbPreviewVersionsAutonomousDbPreviewVersion build() {
            return new GetAutonomousDbPreviewVersionsAutonomousDbPreviewVersion(dbWorkload, details, timePreviewBegin, timePreviewEnd, version);
        }
    }
}
