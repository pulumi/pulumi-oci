// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Adm.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRemediationRunApplicationDependencyRecommendationsApplicationDependencyRecommendationCollectionItem {
    /**
     * @return List of (application dependencies) node identifiers from which this node depends.
     * 
     */
    private List<String> applicationDependencyNodeIds;
    /**
     * @return A filter to return only resources that match the entire GAV (Group Artifact Version) identifier given.
     * 
     */
    private String gav;
    /**
     * @return Unique node identifier of an application dependency with an associated Recommendation, e.g. nodeId1.
     * 
     */
    private String nodeId;
    /**
     * @return A filter to return only resources that match the entire purl given.
     * 
     */
    private String purl;
    /**
     * @return Recommended application dependency in &#34;group:artifact:version&#34; (GAV) format, e.g. org.graalvm.nativeimage:svm:21.2.0.
     * 
     */
    private String recommendedGav;
    /**
     * @return Recommended application dependency in purl format, e.g. pkg:maven/org.graalvm.nativeimage/svm{@literal @}21.2.0
     * 
     */
    private String recommendedPurl;

    private GetRemediationRunApplicationDependencyRecommendationsApplicationDependencyRecommendationCollectionItem() {}
    /**
     * @return List of (application dependencies) node identifiers from which this node depends.
     * 
     */
    public List<String> applicationDependencyNodeIds() {
        return this.applicationDependencyNodeIds;
    }
    /**
     * @return A filter to return only resources that match the entire GAV (Group Artifact Version) identifier given.
     * 
     */
    public String gav() {
        return this.gav;
    }
    /**
     * @return Unique node identifier of an application dependency with an associated Recommendation, e.g. nodeId1.
     * 
     */
    public String nodeId() {
        return this.nodeId;
    }
    /**
     * @return A filter to return only resources that match the entire purl given.
     * 
     */
    public String purl() {
        return this.purl;
    }
    /**
     * @return Recommended application dependency in &#34;group:artifact:version&#34; (GAV) format, e.g. org.graalvm.nativeimage:svm:21.2.0.
     * 
     */
    public String recommendedGav() {
        return this.recommendedGav;
    }
    /**
     * @return Recommended application dependency in purl format, e.g. pkg:maven/org.graalvm.nativeimage/svm{@literal @}21.2.0
     * 
     */
    public String recommendedPurl() {
        return this.recommendedPurl;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRemediationRunApplicationDependencyRecommendationsApplicationDependencyRecommendationCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> applicationDependencyNodeIds;
        private String gav;
        private String nodeId;
        private String purl;
        private String recommendedGav;
        private String recommendedPurl;
        public Builder() {}
        public Builder(GetRemediationRunApplicationDependencyRecommendationsApplicationDependencyRecommendationCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicationDependencyNodeIds = defaults.applicationDependencyNodeIds;
    	      this.gav = defaults.gav;
    	      this.nodeId = defaults.nodeId;
    	      this.purl = defaults.purl;
    	      this.recommendedGav = defaults.recommendedGav;
    	      this.recommendedPurl = defaults.recommendedPurl;
        }

        @CustomType.Setter
        public Builder applicationDependencyNodeIds(List<String> applicationDependencyNodeIds) {
            if (applicationDependencyNodeIds == null) {
              throw new MissingRequiredPropertyException("GetRemediationRunApplicationDependencyRecommendationsApplicationDependencyRecommendationCollectionItem", "applicationDependencyNodeIds");
            }
            this.applicationDependencyNodeIds = applicationDependencyNodeIds;
            return this;
        }
        public Builder applicationDependencyNodeIds(String... applicationDependencyNodeIds) {
            return applicationDependencyNodeIds(List.of(applicationDependencyNodeIds));
        }
        @CustomType.Setter
        public Builder gav(String gav) {
            if (gav == null) {
              throw new MissingRequiredPropertyException("GetRemediationRunApplicationDependencyRecommendationsApplicationDependencyRecommendationCollectionItem", "gav");
            }
            this.gav = gav;
            return this;
        }
        @CustomType.Setter
        public Builder nodeId(String nodeId) {
            if (nodeId == null) {
              throw new MissingRequiredPropertyException("GetRemediationRunApplicationDependencyRecommendationsApplicationDependencyRecommendationCollectionItem", "nodeId");
            }
            this.nodeId = nodeId;
            return this;
        }
        @CustomType.Setter
        public Builder purl(String purl) {
            if (purl == null) {
              throw new MissingRequiredPropertyException("GetRemediationRunApplicationDependencyRecommendationsApplicationDependencyRecommendationCollectionItem", "purl");
            }
            this.purl = purl;
            return this;
        }
        @CustomType.Setter
        public Builder recommendedGav(String recommendedGav) {
            if (recommendedGav == null) {
              throw new MissingRequiredPropertyException("GetRemediationRunApplicationDependencyRecommendationsApplicationDependencyRecommendationCollectionItem", "recommendedGav");
            }
            this.recommendedGav = recommendedGav;
            return this;
        }
        @CustomType.Setter
        public Builder recommendedPurl(String recommendedPurl) {
            if (recommendedPurl == null) {
              throw new MissingRequiredPropertyException("GetRemediationRunApplicationDependencyRecommendationsApplicationDependencyRecommendationCollectionItem", "recommendedPurl");
            }
            this.recommendedPurl = recommendedPurl;
            return this;
        }
        public GetRemediationRunApplicationDependencyRecommendationsApplicationDependencyRecommendationCollectionItem build() {
            final var _resultValue = new GetRemediationRunApplicationDependencyRecommendationsApplicationDependencyRecommendationCollectionItem();
            _resultValue.applicationDependencyNodeIds = applicationDependencyNodeIds;
            _resultValue.gav = gav;
            _resultValue.nodeId = nodeId;
            _resultValue.purl = purl;
            _resultValue.recommendedGav = recommendedGav;
            _resultValue.recommendedPurl = recommendedPurl;
            return _resultValue;
        }
    }
}
