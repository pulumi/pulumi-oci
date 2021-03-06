// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetRepositoryMirrorRecordsRepositoryMirrorRecordCollectionItem {
    private final Map<String,Object> freeformTags;
    /**
     * @return Mirror status of current mirror entry. QUEUED - Mirroring Queued RUNNING - Mirroring is Running PASSED - Mirroring Passed FAILED - Mirroring Failed
     * 
     */
    private final String mirrorStatus;
    private final String timeCompleted;
    /**
     * @return The time to enqueue a mirror operation.
     * 
     */
    private final String timeEnqueued;
    /**
     * @return The time to start a mirror operation.
     * 
     */
    private final String timeStarted;
    /**
     * @return Workrequest ID to track current mirror operation.
     * 
     */
    private final String workRequestId;

    @CustomType.Constructor
    private GetRepositoryMirrorRecordsRepositoryMirrorRecordCollectionItem(
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("mirrorStatus") String mirrorStatus,
        @CustomType.Parameter("timeCompleted") String timeCompleted,
        @CustomType.Parameter("timeEnqueued") String timeEnqueued,
        @CustomType.Parameter("timeStarted") String timeStarted,
        @CustomType.Parameter("workRequestId") String workRequestId) {
        this.freeformTags = freeformTags;
        this.mirrorStatus = mirrorStatus;
        this.timeCompleted = timeCompleted;
        this.timeEnqueued = timeEnqueued;
        this.timeStarted = timeStarted;
        this.workRequestId = workRequestId;
    }

    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Mirror status of current mirror entry. QUEUED - Mirroring Queued RUNNING - Mirroring is Running PASSED - Mirroring Passed FAILED - Mirroring Failed
     * 
     */
    public String mirrorStatus() {
        return this.mirrorStatus;
    }
    public String timeCompleted() {
        return this.timeCompleted;
    }
    /**
     * @return The time to enqueue a mirror operation.
     * 
     */
    public String timeEnqueued() {
        return this.timeEnqueued;
    }
    /**
     * @return The time to start a mirror operation.
     * 
     */
    public String timeStarted() {
        return this.timeStarted;
    }
    /**
     * @return Workrequest ID to track current mirror operation.
     * 
     */
    public String workRequestId() {
        return this.workRequestId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRepositoryMirrorRecordsRepositoryMirrorRecordCollectionItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Map<String,Object> freeformTags;
        private String mirrorStatus;
        private String timeCompleted;
        private String timeEnqueued;
        private String timeStarted;
        private String workRequestId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetRepositoryMirrorRecordsRepositoryMirrorRecordCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.freeformTags = defaults.freeformTags;
    	      this.mirrorStatus = defaults.mirrorStatus;
    	      this.timeCompleted = defaults.timeCompleted;
    	      this.timeEnqueued = defaults.timeEnqueued;
    	      this.timeStarted = defaults.timeStarted;
    	      this.workRequestId = defaults.workRequestId;
        }

        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder mirrorStatus(String mirrorStatus) {
            this.mirrorStatus = Objects.requireNonNull(mirrorStatus);
            return this;
        }
        public Builder timeCompleted(String timeCompleted) {
            this.timeCompleted = Objects.requireNonNull(timeCompleted);
            return this;
        }
        public Builder timeEnqueued(String timeEnqueued) {
            this.timeEnqueued = Objects.requireNonNull(timeEnqueued);
            return this;
        }
        public Builder timeStarted(String timeStarted) {
            this.timeStarted = Objects.requireNonNull(timeStarted);
            return this;
        }
        public Builder workRequestId(String workRequestId) {
            this.workRequestId = Objects.requireNonNull(workRequestId);
            return this;
        }        public GetRepositoryMirrorRecordsRepositoryMirrorRecordCollectionItem build() {
            return new GetRepositoryMirrorRecordsRepositoryMirrorRecordCollectionItem(freeformTags, mirrorStatus, timeCompleted, timeEnqueued, timeStarted, workRequestId);
        }
    }
}
