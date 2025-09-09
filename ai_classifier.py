# ai_classifier.py - AI-Powered IoT Threat Classifier
from transformers import pipeline
import re
import spacy
from collections import Counter
import json

class IoTThreatClassifier:
    def __init__(self):
        """Initialize AI models for IoT threat classification"""
        print("🤖 Loading AI models for IoT classification...")
        
        # Load zero-shot classification model (better for IoT detection)
        try:
            self.zero_shot_classifier = pipeline(
                "zero-shot-classification",
                model="facebook/bart-large-mnli"
            )
            print("✅ Zero-shot classifier loaded")
        except Exception as e:
            print(f"⚠️ Zero-shot classifier failed: {e}")
            self.zero_shot_classifier = None
        
        # Load general text classifier as fallback
        try:
            self.general_classifier = pipeline(
                "text-classification",
                model="distilbert-base-uncased-finetuned-sst-2-english"
            )
            print("✅ General classifier loaded")
        except Exception as e:
            print(f"❌ General classifier failed: {e}")
            self.general_classifier = None
        
        # Load spaCy for entity extraction
        try:
            self.nlp = spacy.load("en_core_web_sm")
            print("✅ spaCy model loaded")
        except Exception as e:
            print(f"❌ spaCy model failed: {e}")
            self.nlp = None
        
        # Define IoT-related terms and categories
        self.iot_categories = [
            "Internet of Things device security",
            "Smart home technology vulnerability", 
            "Connected device security flaw",
            "IoT network protocol issue",
            "Embedded device security"
        ]
        
        self.non_iot_categories = [
            "Web application security",
            "Desktop software vulnerability",
            "Mobile application security",
            "Server software issue",
            "Database security flaw"
        ]
        
        # Comprehensive IoT keyword database
        self.iot_keywords = {
            # Device types
            'smart_devices': [
                'smart home', 'smart house', 'smart device', 'smart appliance',
                'smart thermostat', 'smart camera', 'smart doorbell', 'smart light',
                'smart lock', 'smart tv', 'smart speaker', 'smart switch',
                'smart sensor', 'smart hub', 'smart garage', 'smart alarm',
                'smart smoke detector', 'smart refrigerator', 'smart oven'
            ],
            
            # IoT protocols and technologies
            'protocols': [
                'zigbee', 'z-wave', 'zwave', 'matter', 'thread', 'wifi',
                'bluetooth', 'ble', 'mqtt', 'coap', 'lwm2m', '6lowpan',
                'lora', 'lorawan', 'sigfox', 'nb-iot', 'lpwan'
            ],
            
            # IoT manufacturers and platforms
            'manufacturers': [
                'nest', 'ring', 'alexa', 'google home', 'philips hue',
                'smartthings', 'hubitat', 'wink', 'vera', 'fibaro',
                'arlo', 'wyze', 'tp-link kasa', 'belkin wemo'
            ],
            
            # IoT-specific terms
            'iot_terms': [
                'iot', 'internet of things', 'connected device', 'home automation',
                'home security system', 'surveillance camera', 'ip camera',
                'wireless sensor', 'embedded device', 'firmware',
                'device management', 'remote monitoring'
            ],
            
            # Infrastructure
            'infrastructure': [
                'router', 'gateway', 'access point', 'mesh network',
                'bridge', 'hub', 'controller', 'base station'
            ]
        }
        
        # Flatten keywords for quick lookup
        self.all_iot_keywords = []
        for category, keywords in self.iot_keywords.items():
            self.all_iot_keywords.extend(keywords)
        
        print("🎯 IoT Threat Classifier ready!")
    
    def is_iot_related(self, text, threshold=0.7):
        """Determine if text describes an IoT-related vulnerability"""
        if not text:
            return False, 0.0
        
        text_lower = text.lower()
        
        # Method 1: Keyword-based detection (fast and reliable)
        keyword_score = self._calculate_keyword_score(text_lower)
        
        if keyword_score >= 0.3:  # Strong keyword presence
            return True, keyword_score
        
        # Method 2: AI-based classification (more nuanced)
        if self.zero_shot_classifier:
            try:
                ai_score = self._ai_classification_score(text)
                if ai_score >= threshold:
                    return True, ai_score
            except Exception as e:
                print(f"⚠️ AI classification error: {e}")
        
        # Method 3: Pattern-based detection
        pattern_score = self._pattern_based_score(text_lower)
        if pattern_score >= 0.5:
            return True, pattern_score
        
        # Combine all scores
        final_score = max(keyword_score, pattern_score)
        return final_score >= 0.2, final_score
    
    def _calculate_keyword_score(self, text_lower):
        """Calculate IoT relevance based on keyword presence"""
        score = 0.0
        total_keywords = len(self.all_iot_keywords)
        
        # Weight different categories differently
        weights = {
            'smart_devices': 1.0,
            'iot_terms': 1.0,
            'protocols': 0.8,
            'manufacturers': 0.7,
            'infrastructure': 0.5
        }
        
        for category, keywords in self.iot_keywords.items():
            category_score = 0
            for keyword in keywords:
                if keyword in text_lower:
                    category_score += weights.get(category, 0.5)
            
            # Normalize category score
            if keywords:
                category_score = min(category_score / len(keywords), 1.0)
                score += category_score * weights.get(category, 0.5)
        
        return min(score, 1.0)
    
    def _ai_classification_score(self, text):
        """Use AI to classify IoT relevance"""
        # Truncate text to avoid token limits
        text_truncated = text[:512]
        
        # Combine IoT and non-IoT categories for comparison
        all_categories = self.iot_categories + self.non_iot_categories
        
        result = self.zero_shot_classifier(text_truncated, all_categories)
        
        # Calculate IoT score (sum of IoT category probabilities)
        iot_score = 0.0
        for label, score in zip(result['labels'], result['scores']):
            if label in self.iot_categories:
                iot_score += score
        
        return iot_score
    
    def _pattern_based_score(self, text_lower):
        """Detect IoT relevance using regex patterns"""
        iot_patterns = [
            r'smart \w+',  # smart + any word
            r'iot \w+',    # iot + any word
            r'\w+ camera', # any word + camera
            r'\w+ sensor', # any word + sensor
            r'home automation',
            r'connected \w+',
            r'wireless \w+',
            r'remote \w+ access',
            r'device \w+ vulnerability'
        ]
        
        pattern_matches = 0
        for pattern in iot_patterns:
            if re.search(pattern, text_lower):
                pattern_matches += 1
        
        return min(pattern_matches / len(iot_patterns), 1.0)
    
    def extract_device_info(self, text):
        """Extract specific device information from text"""
        device_info = {
            'device_types': [],
            'manufacturers': [],
            'protocols': [],
            'models': []
        }
        
        text_lower = text.lower()
        
        # Extract device types
        for device in self.iot_keywords['smart_devices']:
            if device in text_lower:
                # Clean up the device name
                device_clean = device.replace('smart ', '').replace(' ', '_')
                device_info['device_types'].append(device_clean)
        
        # Extract manufacturers
        for manufacturer in self.iot_keywords['manufacturers']:
            if manufacturer in text_lower:
                device_info['manufacturers'].append(manufacturer)
        
        # Extract protocols
        for protocol in self.iot_keywords['protocols']:
            if protocol in text_lower:
                device_info['protocols'].append(protocol)
        
        # Extract model numbers using regex
        model_patterns = [
            r'[A-Z]{2,}[-\s]?\d{2,}',  # e.g., WRT-1900, AC1200
            r'v\d+\.\d+',              # e.g., v2.1, v1.0
            r'version \d+\.\d+',       # e.g., version 2.1
            r'firmware \d+\.\d+'       # e.g., firmware 1.0
        ]
        
        for pattern in model_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            device_info['models'].extend(matches)
        
        # Remove duplicates
        for key in device_info:
            device_info[key] = list(set(device_info[key]))
        
        return device_info
    
    def extract_entities(self, text):
        """Extract named entities using spaCy"""
        if not self.nlp:
            return {}
        
        try:
            doc = self.nlp(text)
            entities = {
                'organizations': [],
                'products': [],
                'versions': [],
                'locations': []
            }
            
            for ent in doc.ents:
                if ent.label_ == "ORG":
                    entities['organizations'].append(ent.text)
                elif ent.label_ in ["PRODUCT", "WORK_OF_ART"]:
                    entities['products'].append(ent.text)
                elif ent.label_ in ["CARDINAL", "ORDINAL"]:
                    entities['versions'].append(ent.text)
                elif ent.label_ in ["GPE", "LOC"]:
                    entities['locations'].append(ent.text)
            
            # Remove duplicates
            for key in entities:
                entities[key] = list(set(entities[key]))
            
            return entities
            
        except Exception as e:
            print(f"⚠️ Entity extraction error: {e}")
            return {}
    
    def classify_threat(self, vulnerability_data):
        """Complete classification of a vulnerability"""
        description = vulnerability_data.get('description', '')
        
        if not description:
            return None
        
        # Check if IoT-related
        is_iot, confidence = self.is_iot_related(description)
        
        if not is_iot:
            return None
        
        # Extract detailed information
        device_info = self.extract_device_info(description)
        entities = self.extract_entities(description)
        
        # Compile classification result
        classification = {
            'is_iot_related': True,
            'confidence': confidence,
            'device_info': device_info,
            'entities': entities,
            'classification_method': self._get_classification_method(confidence),
            'original_data': vulnerability_data
        }
        
        return classification
    
    def _get_classification_method(self, confidence):
        """Determine which method provided the classification"""
        if confidence >= 0.7:
            return "high_confidence"
        elif confidence >= 0.5:
            return "medium_confidence"
        else:
            return "low_confidence"


# Test the classifier
if __name__ == "__main__":
    print("🧪 Testing IoT Threat Classifier")
    print("=" * 50)
    
    classifier = IoTThreatClassifier()
    
    # Test cases with varying levels of IoT relevance
    test_cases = [
        {
            'description': "Samsung SmartThings hub vulnerability allows remote code execution via Zigbee protocol",
            'expected': True
        },
        {
            'description': "Smart doorbell camera buffer overflow enables unauthorized video access",
            'expected': True
        },
        {
            'description': "Microsoft Office Excel macro execution vulnerability",
            'expected': False
        },
        {
            'description': "Router firmware update mechanism has authentication bypass",
            'expected': True
        },
        {
            'description': "Nest thermostat WiFi connection sends unencrypted temperature data",
            'expected': True
        },
        {
            'description': "Linux kernel memory corruption in TCP stack",
            'expected': False
        }
    ]
    
    print("\n🔍 Running test cases:")
    correct_predictions = 0
    
    for i, test_case in enumerate(test_cases):
        description = test_case['description']
        expected = test_case['expected']
        
        is_iot, confidence = classifier.is_iot_related(description)
        
        # Extract additional info for IoT cases
        if is_iot:
            device_info = classifier.extract_device_info(description)
            entities = classifier.extract_entities(description)
        else:
            device_info = {}
            entities = {}
        
        # Check if prediction is correct
        correct = (is_iot == expected)
        if correct:
            correct_predictions += 1
        
        print(f"\n{i+1}. {'✅' if correct else '❌'} {description[:60]}...")
        print(f"   Predicted: {'IoT' if is_iot else 'Not IoT'} (confidence: {confidence:.2f})")
        print(f"   Expected: {'IoT' if expected else 'Not IoT'}")
        
        if is_iot and device_info:
            if device_info['device_types']:
                print(f"   Devices: {device_info['device_types']}")
            if device_info['protocols']:
                print(f"   Protocols: {device_info['protocols']}")
    
    accuracy = correct_predictions / len(test_cases)
    print(f"\n📊 Accuracy: {accuracy:.1%} ({correct_predictions}/{len(test_cases)})")
    
    if accuracy >= 0.8:
        print("🎉 Classifier performing well!")
    else:
        print("⚠️ Classifier may need tuning")