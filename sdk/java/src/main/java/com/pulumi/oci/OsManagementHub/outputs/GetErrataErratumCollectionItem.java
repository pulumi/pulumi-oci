// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.outputs.GetErrataErratumCollectionItemPackage;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetErrataErratumCollectionItem {
    /**
     * @return The advisory severity.
     * 
     */
    private String advisorySeverity;
    /**
     * @return A filter to return only errata that match the given advisory types.
     * 
     */
    private String advisoryType;
    /**
     * @return A filter to return only packages that match the given update classification type.
     * 
     */
    private String classificationType;
    /**
     * @return Software source description.
     * 
     */
    private String description;
    /**
     * @return Information specifying from where the erratum was release.
     * 
     */
    private String from;
    /**
     * @return The assigned erratum name. It&#39;s unique and not changeable.  Example: `ELSA-2020-5804`
     * 
     */
    private String name;
    /**
     * @return The OS families the package belongs to.
     * 
     */
    private List<String> osFamilies;
    /**
     * @return List of packages affected by this erratum.
     * 
     */
    private List<GetErrataErratumCollectionItemPackage> packages;
    /**
     * @return Information describing how to find more information about. the erratum.
     * 
     */
    private String references;
    /**
     * @return List of CVEs applicable to this erratum.
     * 
     */
    private List<String> relatedCves;
    /**
     * @return List of repository identifiers.
     * 
     */
    private List<String> repositories;
    /**
     * @return Information describing how the erratum can be resolved.
     * 
     */
    private String solution;
    /**
     * @return Summary description of the erratum.
     * 
     */
    private String synopsis;
    /**
     * @return The date and time the erratum was issued (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    private String timeIssued;
    /**
     * @return The date and time the erratum was updated (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    private String timeUpdated;

    private GetErrataErratumCollectionItem() {}
    /**
     * @return The advisory severity.
     * 
     */
    public String advisorySeverity() {
        return this.advisorySeverity;
    }
    /**
     * @return A filter to return only errata that match the given advisory types.
     * 
     */
    public String advisoryType() {
        return this.advisoryType;
    }
    /**
     * @return A filter to return only packages that match the given update classification type.
     * 
     */
    public String classificationType() {
        return this.classificationType;
    }
    /**
     * @return Software source description.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Information specifying from where the erratum was release.
     * 
     */
    public String from() {
        return this.from;
    }
    /**
     * @return The assigned erratum name. It&#39;s unique and not changeable.  Example: `ELSA-2020-5804`
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The OS families the package belongs to.
     * 
     */
    public List<String> osFamilies() {
        return this.osFamilies;
    }
    /**
     * @return List of packages affected by this erratum.
     * 
     */
    public List<GetErrataErratumCollectionItemPackage> packages() {
        return this.packages;
    }
    /**
     * @return Information describing how to find more information about. the erratum.
     * 
     */
    public String references() {
        return this.references;
    }
    /**
     * @return List of CVEs applicable to this erratum.
     * 
     */
    public List<String> relatedCves() {
        return this.relatedCves;
    }
    /**
     * @return List of repository identifiers.
     * 
     */
    public List<String> repositories() {
        return this.repositories;
    }
    /**
     * @return Information describing how the erratum can be resolved.
     * 
     */
    public String solution() {
        return this.solution;
    }
    /**
     * @return Summary description of the erratum.
     * 
     */
    public String synopsis() {
        return this.synopsis;
    }
    /**
     * @return The date and time the erratum was issued (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    public String timeIssued() {
        return this.timeIssued;
    }
    /**
     * @return The date and time the erratum was updated (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetErrataErratumCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String advisorySeverity;
        private String advisoryType;
        private String classificationType;
        private String description;
        private String from;
        private String name;
        private List<String> osFamilies;
        private List<GetErrataErratumCollectionItemPackage> packages;
        private String references;
        private List<String> relatedCves;
        private List<String> repositories;
        private String solution;
        private String synopsis;
        private String timeIssued;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetErrataErratumCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.advisorySeverity = defaults.advisorySeverity;
    	      this.advisoryType = defaults.advisoryType;
    	      this.classificationType = defaults.classificationType;
    	      this.description = defaults.description;
    	      this.from = defaults.from;
    	      this.name = defaults.name;
    	      this.osFamilies = defaults.osFamilies;
    	      this.packages = defaults.packages;
    	      this.references = defaults.references;
    	      this.relatedCves = defaults.relatedCves;
    	      this.repositories = defaults.repositories;
    	      this.solution = defaults.solution;
    	      this.synopsis = defaults.synopsis;
    	      this.timeIssued = defaults.timeIssued;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder advisorySeverity(String advisorySeverity) {
            if (advisorySeverity == null) {
              throw new MissingRequiredPropertyException("GetErrataErratumCollectionItem", "advisorySeverity");
            }
            this.advisorySeverity = advisorySeverity;
            return this;
        }
        @CustomType.Setter
        public Builder advisoryType(String advisoryType) {
            if (advisoryType == null) {
              throw new MissingRequiredPropertyException("GetErrataErratumCollectionItem", "advisoryType");
            }
            this.advisoryType = advisoryType;
            return this;
        }
        @CustomType.Setter
        public Builder classificationType(String classificationType) {
            if (classificationType == null) {
              throw new MissingRequiredPropertyException("GetErrataErratumCollectionItem", "classificationType");
            }
            this.classificationType = classificationType;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetErrataErratumCollectionItem", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder from(String from) {
            if (from == null) {
              throw new MissingRequiredPropertyException("GetErrataErratumCollectionItem", "from");
            }
            this.from = from;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetErrataErratumCollectionItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder osFamilies(List<String> osFamilies) {
            if (osFamilies == null) {
              throw new MissingRequiredPropertyException("GetErrataErratumCollectionItem", "osFamilies");
            }
            this.osFamilies = osFamilies;
            return this;
        }
        public Builder osFamilies(String... osFamilies) {
            return osFamilies(List.of(osFamilies));
        }
        @CustomType.Setter
        public Builder packages(List<GetErrataErratumCollectionItemPackage> packages) {
            if (packages == null) {
              throw new MissingRequiredPropertyException("GetErrataErratumCollectionItem", "packages");
            }
            this.packages = packages;
            return this;
        }
        public Builder packages(GetErrataErratumCollectionItemPackage... packages) {
            return packages(List.of(packages));
        }
        @CustomType.Setter
        public Builder references(String references) {
            if (references == null) {
              throw new MissingRequiredPropertyException("GetErrataErratumCollectionItem", "references");
            }
            this.references = references;
            return this;
        }
        @CustomType.Setter
        public Builder relatedCves(List<String> relatedCves) {
            if (relatedCves == null) {
              throw new MissingRequiredPropertyException("GetErrataErratumCollectionItem", "relatedCves");
            }
            this.relatedCves = relatedCves;
            return this;
        }
        public Builder relatedCves(String... relatedCves) {
            return relatedCves(List.of(relatedCves));
        }
        @CustomType.Setter
        public Builder repositories(List<String> repositories) {
            if (repositories == null) {
              throw new MissingRequiredPropertyException("GetErrataErratumCollectionItem", "repositories");
            }
            this.repositories = repositories;
            return this;
        }
        public Builder repositories(String... repositories) {
            return repositories(List.of(repositories));
        }
        @CustomType.Setter
        public Builder solution(String solution) {
            if (solution == null) {
              throw new MissingRequiredPropertyException("GetErrataErratumCollectionItem", "solution");
            }
            this.solution = solution;
            return this;
        }
        @CustomType.Setter
        public Builder synopsis(String synopsis) {
            if (synopsis == null) {
              throw new MissingRequiredPropertyException("GetErrataErratumCollectionItem", "synopsis");
            }
            this.synopsis = synopsis;
            return this;
        }
        @CustomType.Setter
        public Builder timeIssued(String timeIssued) {
            if (timeIssued == null) {
              throw new MissingRequiredPropertyException("GetErrataErratumCollectionItem", "timeIssued");
            }
            this.timeIssued = timeIssued;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetErrataErratumCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetErrataErratumCollectionItem build() {
            final var _resultValue = new GetErrataErratumCollectionItem();
            _resultValue.advisorySeverity = advisorySeverity;
            _resultValue.advisoryType = advisoryType;
            _resultValue.classificationType = classificationType;
            _resultValue.description = description;
            _resultValue.from = from;
            _resultValue.name = name;
            _resultValue.osFamilies = osFamilies;
            _resultValue.packages = packages;
            _resultValue.references = references;
            _resultValue.relatedCves = relatedCves;
            _resultValue.repositories = repositories;
            _resultValue.solution = solution;
            _resultValue.synopsis = synopsis;
            _resultValue.timeIssued = timeIssued;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
