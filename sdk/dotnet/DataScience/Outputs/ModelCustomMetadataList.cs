// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Outputs
{

    [OutputType]
    public sealed class ModelCustomMetadataList
    {
        /// <summary>
        /// (Updatable) Category of model metadata which should be null for defined metadata.For custom metadata is should be one of the following values "Performance,Training Profile,Training and Validation Datasets,Training Environment,Reports,Readme,other".
        /// </summary>
        public readonly string? Category;
        /// <summary>
        /// (Updatable) Description of model metadata
        /// </summary>
        public readonly string? Description;
        /// <summary>
        /// (Updatable) Key of the model Metadata. The key can either be user defined or Oracle Cloud Infrastructure defined. List of Oracle Cloud Infrastructure defined keys:
        /// * useCaseType
        /// * libraryName
        /// * libraryVersion
        /// * estimatorClass
        /// * hyperParameters
        /// * testArtifactresults
        /// </summary>
        public readonly string? Key;
        /// <summary>
        /// (Updatable) Allowed values for useCaseType: binary_classification, regression, multinomial_classification, clustering, recommender, dimensionality_reduction/representation, time_series_forecasting, anomaly_detection, topic_modeling, ner, sentiment_analysis, image_classification, object_localization, other
        /// 
        /// Allowed values for libraryName: scikit-learn, xgboost, tensorflow, pytorch, mxnet, keras, lightGBM, pymc3, pyOD, spacy, prophet, sktime, statsmodels, cuml, oracle_automl, h2o, transformers, nltk, emcee, pystan, bert, gensim, flair, word2vec, ensemble, other
        /// </summary>
        public readonly string? Value;

        [OutputConstructor]
        private ModelCustomMetadataList(
            string? category,

            string? description,

            string? key,

            string? value)
        {
            Category = category;
            Description = description;
            Key = key;
            Value = value;
        }
    }
}
