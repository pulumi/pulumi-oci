// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmTraces.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApmTraces.outputs.GetTraceSnapshotDataTraceSnapshotDetail;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetTraceSnapshotDataResult {
    private String apmDomainId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable Boolean isSummarized;
    /**
     * @return Name of the property.
     * 
     */
    private String key;
    private @Nullable String snapshotTime;
    private @Nullable String threadId;
    /**
     * @return End time of the trace.
     * 
     */
    private String timeEnded;
    /**
     * @return Start time of the trace.
     * 
     */
    private String timeStarted;
    private String traceKey;
    /**
     * @return Trace snapshots properties.
     * 
     */
    private List<GetTraceSnapshotDataTraceSnapshotDetail> traceSnapshotDetails;

    private GetTraceSnapshotDataResult() {}
    public String apmDomainId() {
        return this.apmDomainId;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<Boolean> isSummarized() {
        return Optional.ofNullable(this.isSummarized);
    }
    /**
     * @return Name of the property.
     * 
     */
    public String key() {
        return this.key;
    }
    public Optional<String> snapshotTime() {
        return Optional.ofNullable(this.snapshotTime);
    }
    public Optional<String> threadId() {
        return Optional.ofNullable(this.threadId);
    }
    /**
     * @return End time of the trace.
     * 
     */
    public String timeEnded() {
        return this.timeEnded;
    }
    /**
     * @return Start time of the trace.
     * 
     */
    public String timeStarted() {
        return this.timeStarted;
    }
    public String traceKey() {
        return this.traceKey;
    }
    /**
     * @return Trace snapshots properties.
     * 
     */
    public List<GetTraceSnapshotDataTraceSnapshotDetail> traceSnapshotDetails() {
        return this.traceSnapshotDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTraceSnapshotDataResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String apmDomainId;
        private String id;
        private @Nullable Boolean isSummarized;
        private String key;
        private @Nullable String snapshotTime;
        private @Nullable String threadId;
        private String timeEnded;
        private String timeStarted;
        private String traceKey;
        private List<GetTraceSnapshotDataTraceSnapshotDetail> traceSnapshotDetails;
        public Builder() {}
        public Builder(GetTraceSnapshotDataResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apmDomainId = defaults.apmDomainId;
    	      this.id = defaults.id;
    	      this.isSummarized = defaults.isSummarized;
    	      this.key = defaults.key;
    	      this.snapshotTime = defaults.snapshotTime;
    	      this.threadId = defaults.threadId;
    	      this.timeEnded = defaults.timeEnded;
    	      this.timeStarted = defaults.timeStarted;
    	      this.traceKey = defaults.traceKey;
    	      this.traceSnapshotDetails = defaults.traceSnapshotDetails;
        }

        @CustomType.Setter
        public Builder apmDomainId(String apmDomainId) {
            this.apmDomainId = Objects.requireNonNull(apmDomainId);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder isSummarized(@Nullable Boolean isSummarized) {
            this.isSummarized = isSummarized;
            return this;
        }
        @CustomType.Setter
        public Builder key(String key) {
            this.key = Objects.requireNonNull(key);
            return this;
        }
        @CustomType.Setter
        public Builder snapshotTime(@Nullable String snapshotTime) {
            this.snapshotTime = snapshotTime;
            return this;
        }
        @CustomType.Setter
        public Builder threadId(@Nullable String threadId) {
            this.threadId = threadId;
            return this;
        }
        @CustomType.Setter
        public Builder timeEnded(String timeEnded) {
            this.timeEnded = Objects.requireNonNull(timeEnded);
            return this;
        }
        @CustomType.Setter
        public Builder timeStarted(String timeStarted) {
            this.timeStarted = Objects.requireNonNull(timeStarted);
            return this;
        }
        @CustomType.Setter
        public Builder traceKey(String traceKey) {
            this.traceKey = Objects.requireNonNull(traceKey);
            return this;
        }
        @CustomType.Setter
        public Builder traceSnapshotDetails(List<GetTraceSnapshotDataTraceSnapshotDetail> traceSnapshotDetails) {
            this.traceSnapshotDetails = Objects.requireNonNull(traceSnapshotDetails);
            return this;
        }
        public Builder traceSnapshotDetails(GetTraceSnapshotDataTraceSnapshotDetail... traceSnapshotDetails) {
            return traceSnapshotDetails(List.of(traceSnapshotDetails));
        }
        public GetTraceSnapshotDataResult build() {
            final var o = new GetTraceSnapshotDataResult();
            o.apmDomainId = apmDomainId;
            o.id = id;
            o.isSummarized = isSummarized;
            o.key = key;
            o.snapshotTime = snapshotTime;
            o.threadId = threadId;
            o.timeEnded = timeEnded;
            o.timeStarted = timeStarted;
            o.traceKey = traceKey;
            o.traceSnapshotDetails = traceSnapshotDetails;
            return o;
        }
    }
}